/*
 * ### IP:.getMe GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package nsis;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import nsis.file.NsisConstants;
import nsis.file.NsisExecutable;
import nsis.format.InvalidFormatException;
import nsis.format.NsisCommonHeader;
import nsis.format.NsisCrc;
import nsis.format.NsisEntry;
import nsis.format.NsisFirstHeader;
import nsis.format.NsisPage;
import nsis.format.NsisSection;

public class NsisLoader extends AbstractLibrarySupportLoader {

  public final static String NE_NAME = "NSIS Executable (Nullsoft Scriptable Install System)";

  @Override
  public String getName() {
    return NE_NAME;
  }

  @Override
  public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
    List<LoadSpec> loadSpecs = new ArrayList<>();
    try {
      NsisExecutable ne = NsisExecutable.createNsisExecutable(RethrowContinuesFactory.INSTANCE,
          provider);
      LoadSpec my_spec = new LoadSpec(this, ne.getHeaderOffset(),
          new LanguageCompilerSpecPair("Nsis:LE:32:default", "default"), true);
      loadSpecs.add(my_spec);
    } catch (InvalidFormatException e) {
      // Not a Nsis file, no loading spec added
      // Do nothing
    }
    return loadSpecs;
  }

  @Override
  protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
      Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
    try {
      GenericFactory factory = MessageLogContinuesFactory.create(log);
      NsisExecutable ne = NsisExecutable.createInitializeNsisExecutable(factory, provider,
          SectionLayout.FILE);
      long scriptHeaderOffset = ne.getHeaderOffset();

      Address firstHeaderAddress = program.getAddressFactory().getDefaultAddressSpace()
          .getAddress(scriptHeaderOffset);

      try (InputStream headerInputStream = provider.getInputStream(scriptHeaderOffset)) {
        initFirstHeader(headerInputStream, firstHeaderAddress, program, monitor);
      }

      try (InputStream bodyInputStream = ne.getDecompressedInputStream()) {
        long currentOffset = ne.getHeaderOffset() + NsisFirstHeader.getHeaderSize();
        Address commonHeaderAddress = firstHeaderAddress.add(NsisFirstHeader.getHeaderSize());
        currentOffset += initCommonHeader(bodyInputStream, commonHeaderAddress, program, monitor);

        Address pagesSectionAddress = commonHeaderAddress
            .add(ne.getSectionOffset(NsisConstants.BlockHeaderType.PAGES));
        currentOffset += accountForPadding(currentOffset, pagesSectionAddress.getOffset(),
            bodyInputStream);
        currentOffset += initPagesSection(bodyInputStream, pagesSectionAddress, program, monitor,
            ne.getNumPages());

        Address sectionHeadersAddress = commonHeaderAddress
            .add(ne.getSectionOffset(NsisConstants.BlockHeaderType.SECTIONS));
        currentOffset += accountForPadding(currentOffset, sectionHeadersAddress.getOffset(),
            bodyInputStream);
        currentOffset += initSectionHeaders(bodyInputStream, sectionHeadersAddress, program,
            monitor, ne.getNumSections());

        Address entriesSectionAddress = commonHeaderAddress
            .add(ne.getSectionOffset(NsisConstants.BlockHeaderType.ENTRIES));
        currentOffset += accountForPadding(currentOffset, entriesSectionAddress.getOffset(),
            bodyInputStream);
        currentOffset += initEntriesSection(bodyInputStream, entriesSectionAddress, program,
            monitor, ne.getNumEntries());

        Address stringsAddress = commonHeaderAddress
            .add(ne.getSectionOffset(NsisConstants.BlockHeaderType.STRINGS));
        currentOffset += accountForPadding(currentOffset, stringsAddress.getOffset(),
            bodyInputStream);
        currentOffset += initStringsSection(bodyInputStream, stringsAddress, program, monitor,
            ne.getStringsSectionSize());

        Address langTablesAddress = commonHeaderAddress
            .add(ne.getSectionOffset(NsisConstants.BlockHeaderType.LANGTABLES));
        currentOffset += accountForPadding(currentOffset, langTablesAddress.getOffset(),
            bodyInputStream);
        currentOffset += initLangTablesSection(bodyInputStream, langTablesAddress, program, monitor,
            ne.getLangTablesSectionSize());

        Address ctlColorsAddress = commonHeaderAddress
            .add(ne.getSectionOffset(NsisConstants.BlockHeaderType.CONTROL_COLORS));
        currentOffset += accountForPadding(currentOffset, ctlColorsAddress.getOffset(),
            bodyInputStream);
        currentOffset += initCtlColorsSection(bodyInputStream, ctlColorsAddress, program, monitor,
            ne.getControlColorsSectionSize());
      }

      try (InputStream crcInputStream = provider.getInputStream(ne.getCrcOffset())) {
        Address lastSetAddress = program.getMemory().getLoadedAndInitializedAddressSet()
            .getMaxAddress();
        initCrcSection(crcInputStream, lastSetAddress.add(1), program, monitor);
      }

    } catch (Exception e) {
      throw new IOException(e); // Ghidra handles the thrown exception
    }
  }

  /**
   * Determines if there is any padding between the sections or blocks and
   * advances the input stream if so
   * 
   * @param currentOffset The current offset in the input stream
   * @param nextOffset          The next offset that needs to be read from
   * @param is                  The input stream, the function has the side effect
   *                            of advancing the input stream is required
   * @return The size of padding, also equals how many bytes the input stream was
   *         advanced
   * @throws IOException
   */
  private long accountForPadding(
      long currentOffset, long nextOffset, InputStream is)
      throws IOException {
    long paddingSize = nextOffset - currentOffset;
    if (paddingSize > 0) {
      currentOffset += paddingSize;
      is.skip(paddingSize);
    }
    return paddingSize;
  }

  /**
   * Applies the DataType structure to the data at given address.
   * 
   * @param program
   * @param listing
   * @param address  at which to apply the data structure
   * @param dataType to apply to the bytes
   * @return
   * @throws CodeUnitInsertionException
   */
  private Data createData(Program program, Address address, DataType dt)
      throws CodeUnitInsertionException {
    Listing listing = program.getListing();
    Data d = listing.getDataAt(address);
    if (d == null || !dt.isEquivalent(d.getDataType())) {
      d = DataUtilities.createData(program, address, dt, -1, false,
          ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
    }
    return d;
  }

  /**
   * 
   * Initializes a memory block in Ghidra with the given permissions and the given
   * data
   * 
   * @param is                InputStream of the data
   * @param startingAddr
   * @param program
   * @param monitor
   * @param size
   * @param blockName
   * @param readPermission
   * @param writePermission
   * @param executePermission
   * @throws DuplicateNameException
   * @throws CancelledException
   * @throws AddressOverflowException
   * @throws MemoryConflictException
   * @throws LockException
   */
  private void createGhidraMemoryBlock(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, long size, String blockName, boolean readPermission,
      boolean writePermission, boolean executePermission)
      throws LockException, MemoryConflictException, AddressOverflowException, CancelledException,
      DuplicateNameException {
    Memory memory = program.getMemory();
    MemoryBlock firstHeaderBlock = memory.createInitializedBlock(blockName, startingAddr, is, size,
        monitor, /* Overlay */ false);
    firstHeaderBlock.setRead(readPermission);
    firstHeaderBlock.setWrite(writePermission);
    firstHeaderBlock.setExecute(executePermission);
  }

  /**
   * Initializes the first header and adds it to the "Program Trees" view in
   * Ghidra.
   * 
   * @param fileBytes            object that starts at the NSIS magic bytes
   * @param scriptHeaderAddress, the address at which the nsis script header
   *                             starts
   * @param size                 of the header
   * @param program              object
   * @param dataType             of the script header
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   * @throws LockException
   * @throws CodeUnitInsertionException
   */
  private void initFirstHeader(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor) throws MemoryConflictException, AddressOverflowException,
      CancelledException, DuplicateNameException, LockException, CodeUnitInsertionException {

    boolean readPermission = true;
    boolean writePermission = false;
    boolean executePermission = false;
    createGhidraMemoryBlock(is, startingAddr, program, monitor, NsisFirstHeader.getHeaderSize(),
        NsisConstants.FIRST_HEADER_MEMORY_BLOCK_NAME, readPermission, writePermission,
        executePermission);
    createData(program, startingAddr, NsisFirstHeader.STRUCTURE);
  }

  /**
   * Initializes the common header and adds it to the "Program Trees" view in
   * Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param dataType
   * @param monitor
   * @param size
   * @return The number of bytes the input stream was advanced
   * @throws IOException
   * @throws LockException
   * @throws DuplicateNameException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws CodeUnitInsertionException
   */
  private long initCommonHeader(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException,
      CancelledException, DuplicateNameException, CodeUnitInsertionException {

    boolean readPermission = true;
    boolean writePermission = false;
    boolean executePermission = false;
    createGhidraMemoryBlock(is, startingAddr, program, monitor, NsisCommonHeader.getHeaderSize(),
        NsisConstants.COMMON_HEADER_MEMORY_BLOCK_NAME, readPermission, writePermission,
        executePermission);
    createData(program, startingAddr, NsisCommonHeader.STRUCTURE);

    return NsisCommonHeader.getHeaderSize();
  }

  /**
   * Initializes the pages section and adds the section to the "program Trees"
   * view in Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param dataType
   * @param monitor
   * @param size
   * @param numPages
   * @return The number bytes the input stream was advanced
   * @throws IOException
   * @throws LockException
   * @throws DuplicateNameException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws CodeUnitInsertionException
   * @throws InvalidNameException
   */
  private long initPagesSection(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, int numPages) throws IOException, LockException, DuplicateNameException,
      MemoryConflictException, AddressOverflowException, CancelledException,
      CodeUnitInsertionException, InvalidNameException {

    if (numPages > 0) {
      boolean readPermission = true;
      boolean writePermission = false;
      boolean executePermission = false;
      createGhidraMemoryBlock(is, startingAddr, program, monitor, NsisPage.getPageSize() * numPages,
          NsisConstants.PAGES_MEMORY_BLOCK_NAME, readPermission, writePermission,
          executePermission);

      for (int i = 0; i < numPages; i++) {
        NsisPage.STRUCTURE.setName("Page #" + (i + 1));
        createData(program, startingAddr, NsisPage.STRUCTURE);
        startingAddr = startingAddr.add(NsisPage.getPageSize());
      }
      return NsisPage.getPageSize() * numPages;
    }
    return 0;
  }

  /**
   * Initializes the section headers section and adds it to the "program Trees"
   * view in Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param monitor
   * @return Number of bytes the input stream was advanced
   * @throws LockException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   * @throws CodeUnitInsertionException
   * @throws InvalidNameException
   */
  private long initSectionHeaders(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, int numSections)
      throws LockException, MemoryConflictException, AddressOverflowException, CancelledException,
      DuplicateNameException, CodeUnitInsertionException, InvalidNameException {

    if (numSections > 0) {
      boolean readPermission = true;
      boolean writePermission = false;
      boolean executePermission = false;
      createGhidraMemoryBlock(is, startingAddr, program, monitor,
          NsisSection.getSectionSize() * numSections, NsisConstants.SECTIONS_MEMORY_BLOCK_NAME,
          readPermission, writePermission, executePermission);

      for (int i = 0; i < numSections; i++) {
        NsisSection.STRUCTURE.setName("Section #" + (i + 1));
        createData(program, startingAddr, NsisSection.STRUCTURE);
        startingAddr = startingAddr.add(NsisSection.getSectionSize());
      }
      return NsisSection.getSectionSize() * numSections;
    }
    return 0;
  }

  /**
   * 
   * Initializes the entries section and adds the section to the "program Trees"
   * view in Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param monitor
   * @param size
   * @return The number of bytes the input stream was advanced
   * @throws LockException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   * @throws CodeUnitInsertionException
   */
  private long initEntriesSection(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, int numEntries)
      throws LockException, MemoryConflictException, AddressOverflowException, CancelledException,
      DuplicateNameException, CodeUnitInsertionException {

    if (numEntries > 0) {
      boolean readPermission = true;
      boolean writePermission = false;
      boolean executePermission = true;

      createGhidraMemoryBlock(is, startingAddr, program, monitor,
          NsisEntry.getEntrySize() * numEntries, NsisConstants.ENTRIES_MEMORY_BLOCK_NAME,
          readPermission, writePermission, executePermission);
      return NsisEntry.getEntrySize() * numEntries;
    }
    return 0;
  }

  /**
   * Initializes the strings section and adds the it to the "program Trees" view
   * in Ghidra. Please not this function will not analyze the section to create
   * the strings as the ASCII strings analyzer is available for this purpose.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param monitor
   * @param sectionLength
   * @returns The number of bytes the input stream was advanced
   * @throws LockException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   */
  private long initStringsSection(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, long sectionLength) throws LockException, MemoryConflictException,
      AddressOverflowException, CancelledException, DuplicateNameException {

    if (sectionLength > 0) {
      boolean readPermission = true;
      boolean writePermission = false;
      boolean executePermission = false;
      createGhidraMemoryBlock(is, startingAddr, program, monitor, sectionLength,
          NsisConstants.STRINGS_MEMORY_BLOCK_NAME, readPermission, writePermission,
          executePermission);
      return sectionLength;
    }
    return 0;
  }

  /**
   * Initializes the langTables section and adds the it to the "program Trees"
   * view in Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param monitor
   * @param sectionLength
   * @return The number of bytes the input stream was advanced
   * @throws LockException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   */
  private long initLangTablesSection(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, long sectionLength) throws LockException, MemoryConflictException,
      AddressOverflowException, CancelledException, DuplicateNameException {

    if (sectionLength > 0) {
      boolean readPermission = true;
      boolean writePermission = false;
      boolean executePermission = false;
      createGhidraMemoryBlock(is, startingAddr, program, monitor, sectionLength,
          NsisConstants.LANGTABLES_MEMORY_BLOCK_NAME, readPermission, writePermission,
          executePermission);
      return sectionLength;
    }
    return 0;
  }

  /**
   * Initializes the ctlColors section and adds the it to the "program Trees" view
   * in Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param monitor
   * @param sectionLength
   * @return The number of bytes the input stream was advanced
   * @throws LockException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   */
  private long initCtlColorsSection(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor, long sectionLength) throws LockException, MemoryConflictException,
      AddressOverflowException, CancelledException, DuplicateNameException {

    if (sectionLength > 0) {
      boolean readPermission = true;
      boolean writePermission = false;
      boolean executePermission = false;
      createGhidraMemoryBlock(is, startingAddr, program, monitor, sectionLength,
          NsisConstants.CONTROL_COLORS_MEMORY_BLOCK_NAME, readPermission, writePermission,
          executePermission);
      return sectionLength;
    }
    return 0;
  }

  /**
   * Initializes the CRC section and adds the it to the "program Trees" view in
   * Ghidra.
   * 
   * @param is
   * @param startingAddr
   * @param program
   * @param monitor
   * @param sectionLength
   * @throws LockException
   * @throws MemoryConflictException
   * @throws AddressOverflowException
   * @throws CancelledException
   * @throws DuplicateNameException
   * @throws CodeUnitInsertionException
   */
  private void initCrcSection(InputStream is, Address startingAddr, Program program,
      TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException,
      CancelledException, DuplicateNameException, CodeUnitInsertionException {

    boolean readPermission = true;
    boolean writePermission = false;
    boolean executePermission = false;
    createGhidraMemoryBlock(is, startingAddr, program, monitor, NsisConstants.NSIS_CRC_LENGTH,
        NsisConstants.CRC_SIGNATURE_MEMORY_BLOCK_NAME, readPermission, writePermission,
        executePermission);
    createData(program, startingAddr, NsisCrc.STRUCTURE);
  }

}
