package nsis.file;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import com.google.common.primitives.Bytes;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import nsis.compression.NsisBzipProvider;
import nsis.compression.NsisDecompressionProvider;
import nsis.compression.NsisLZMAProvider;
import nsis.compression.NsisUncompressedProvider;
import nsis.compression.NsisZlibProvider;
import nsis.format.InvalidFormatException;
import nsis.format.NsisBlockHeader;
import nsis.format.NsisCommonHeader;
import nsis.format.NsisControlColors;
import nsis.format.NsisCrc;
import nsis.format.NsisEntry;
import nsis.format.NsisFirstHeader;
import nsis.format.NsisLangTables;
import nsis.format.NsisPage;
import nsis.format.NsisSection;
import nsis.format.NsisStrings;

/**
 * 
 * This class represents a Nsis Executable.
 *
 */
public class NsisExecutable {

  public static final String NAME = "NULLSOFT_SCRIPTABLE_INSTALLER_SYSTEM";
  public static final int FLAG_IS_COMPRESSED = 0x80000000;

  private BinaryReader reader;
  private long headerOffset;
  private long crcSignatureOffset;
  private NsisDecompressionProvider decompressionProvider;
  private NsisFirstHeader firstHeader;
  private NsisCommonHeader commonHeader;
  private NsisPage[] pages;
  private NsisSection[] sections;
  private NsisEntry[] entries;
  private NsisStrings strings;
  private NsisLangTables langTables;
  private NsisControlColors ctlColors;
  private NsisCrc crc;

  /**
   * Use createNsisExecutable to create a Nsis Executable object
   */
  public NsisExecutable() {}

  /**
   * Creates and initializes a Nsis Executable object
   * 
   * @param factory that will be used to create Nsis Executable
   * @param byteProvider object that will permit reading bytes from the file. The lifespan of the
   *        byte provider is controlled by Ghidra.
   * @param layout object used to load PE executables
   * @return The Nsis executable object
   * @throws IOException
   * @throws InvalidFormatException
   */
  public static NsisExecutable createInitializeNsisExecutable(GenericFactory factory,
      ByteProvider bp, SectionLayout layout) throws IOException, InvalidFormatException {
    NsisExecutable nsisExecutable = NsisExecutable.createNsisExecutable(factory, bp);
    nsisExecutable.initNsisExecutable(factory);
    return nsisExecutable;
  }

  /**
   * Creates a Nsis Executable object, sets the reader and the offset parameter. To create and
   * initialize a Nsis Executable object, use createInitializeNsisExecutable.
   * 
   * @param factory
   * @param bp
   * @throws IOException
   * @throws InvalidFormatException
   */
  public static NsisExecutable createNsisExecutable(GenericFactory factory, ByteProvider bp)
      throws IOException, InvalidFormatException {
    NsisExecutable nsisExecutable = (NsisExecutable) factory.create(NsisExecutable.class);
    nsisExecutable.reader =
        new FactoryBundledWithBinaryReader(factory, bp, NsisConstants.IS_LITTLE_ENDIAN);
    nsisExecutable.headerOffset = nsisExecutable.findHeaderOffset();
    return nsisExecutable;
  }

  private void initNsisExecutable(GenericFactory factory)
      throws IOException, InvalidFormatException {
    initFirstHeader();
    this.crcSignatureOffset =
        this.headerOffset + (this.firstHeader.archiveSize - NsisConstants.NSIS_CRC_LENGTH);
    this.decompressionProvider = getDecompressionProvider();
    try (InputStream decompressesdStream = this.getDecompressedInputStream()) {
      ByteProvider blockDataByteProvider =
          new InputStreamByteProvider(decompressesdStream, this.firstHeader.inflatedHeaderSize);
      BinaryReader blockReader = new FactoryBundledWithBinaryReader(factory, blockDataByteProvider,
          NsisConstants.IS_LITTLE_ENDIAN);
      this.commonHeader = new NsisCommonHeader(blockReader);
      blockReader.setPointerIndex(this.getSectionOffset(NsisConstants.BlockHeaderType.PAGES));
      this.pages = getPages(blockReader);
      blockReader.setPointerIndex(this.getSectionOffset(NsisConstants.BlockHeaderType.SECTIONS));
      this.sections = getSections(blockReader);
      blockReader.setPointerIndex(this.getSectionOffset(NsisConstants.BlockHeaderType.ENTRIES));
      this.entries = getEntries(blockReader);
      initStrings(blockReader);
      initLangTables(blockReader);
      initCtlColors(blockReader);
      initCrc();
    }
  }

  /**
   * Get an array of the right amount of pages in the Nsis executable. The reader object is expected
   * to be at the right offset (at the beginning of the first page) before calling this function.
   * The reader index is advanced and after executing this function, the index of the reader is
   * pointing to the first byte after the pages section.
   * 
   * @param reader
   * @return NsisPage array that contains all the pages in the Nsis executable
   * @throws IOException
   */
  private NsisPage[] getPages(BinaryReader reader) throws IOException {
    NsisBlockHeader pagesBlockHeader =
        this.commonHeader.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal());
    NsisPage[] pages = new NsisPage[pagesBlockHeader.getNumEntries()];
    for (int i = 0; i < pages.length; i++) {
      pages[i] = new NsisPage(reader);
    }
    return pages;
  }

  /**
   * Get an array of the right amount of sections in the Nsis executable. The reader object is
   * expected to be at the right offset (at the beginning of the first section) before calling this
   * function. The reader index is advanced and after executing this function, the index of the
   * reader is pointing to the first byte after the section headers section.
   * 
   * @param reader
   * @return
   * @throws IOException
   */
  private NsisSection[] getSections(BinaryReader reader) throws IOException {
    NsisBlockHeader sectionBlockHeader =
        this.commonHeader.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal());
    NsisSection[] sections = new NsisSection[sectionBlockHeader.getNumEntries()];
    for (int i = 0; i < sections.length; i++) {
      sections[i] = new NsisSection(reader);
    }
    return sections;
  }

  /**
   * Get an array of the right amount of entries in the Nsis executable. The reader object is
   * expected to be at the right offset (at the beginning of the first entry) before calling this
   * function. The reader index is advanced and after executing this function, the index of the
   * reader is pointing to the first byte after the entries section.
   * 
   * @param reader
   * @return
   * @throws IOException
   */
  private NsisEntry[] getEntries(BinaryReader reader) throws IOException {
    NsisBlockHeader entriesBlockHeader =
        this.commonHeader.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal());
    NsisEntry[] entries = new NsisEntry[entriesBlockHeader.getNumEntries()];
    for (int i = 0; i < entries.length; i++) {
      entries[i] = new NsisEntry(reader);
    }
    return entries;
  }

  /**
   * Initializes the strings section. After passing through this function, the BinaryReader's index
   * will be at the end of the strings section.
   * 
   * @param reader
   */
  private void initStrings(BinaryReader reader) {
    reader.setPointerIndex(this.getSectionOffset(NsisConstants.BlockHeaderType.STRINGS));
    long stringsSectionLength = getSectionSizeFromOffsets(
        this.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset(),
        this.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
    this.strings = new NsisStrings(reader, stringsSectionLength);
  }

  /**
   * Initializes the langTables section. After passing through this function, the BinaryReader's
   * index will be at the end of the langTables section.
   * 
   * @param reader
   */
  private void initLangTables(BinaryReader reader) {
    reader.setPointerIndex(this.getSectionOffset(NsisConstants.BlockHeaderType.LANGTABLES));
    long langTablesSectionLength = getSectionSizeFromOffsets(
        this.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset(),
        this.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
    this.langTables = new NsisLangTables(reader, langTablesSectionLength);
  }

  /**
   * Initializes the ctlColors section. After passing through this function, the BinaryReader's
   * index will be at the end of the ctlColors section.
   * 
   * @param reader
   */
  private void initCtlColors(BinaryReader reader) {
    reader.setPointerIndex(this.getSectionOffset(NsisConstants.BlockHeaderType.CONTROL_COLORS));
    long ctlColorsSectionLength = getSectionSizeFromOffsets(
        this.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset(),
        this.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
    this.ctlColors = new NsisControlColors(reader, ctlColorsSectionLength);
  }

  private long findHeaderOffset() throws IOException, InvalidFormatException {
    for (long headerOffset = 0; headerOffset + NsisConstants.NSIS_SIGINFO.length
        + NsisConstants.NSIS_MAGIC.length <= reader.length(); headerOffset++) {
      byte[] content = reader.readByteArray(headerOffset,
          NsisConstants.NSIS_SIGINFO.length + NsisConstants.NSIS_MAGIC.length);
      if (Arrays.equals(Bytes.concat(NsisConstants.NSIS_SIGINFO, NsisConstants.NSIS_MAGIC),
          content)) {
        return headerOffset - StructConverter.DWORD.getLength(); // Include flag in header
      }
    }
    throw new InvalidFormatException("Nsis magic not found.");
  }

  /**
   * Initializes the CRC signature bytes. After passing through this function, the binary reader's
   * index will be at the beginning of the CRC.
   * 
   * @throws IOException
   */
  private void initCrc() throws IOException {
    this.reader.setPointerIndex(this.crcSignatureOffset);
    this.crc = new NsisCrc(this.reader);
  }

  /**
   * Initializes the script header.
   * 
   * @throws IOException
   * @throws InvalidFormatException
   */
  private void initFirstHeader() throws IOException, InvalidFormatException {
    this.reader.setPointerIndex(this.headerOffset);
    this.firstHeader = new NsisFirstHeader(this.reader);
  }

  /**
   * Attempt to decompress the data from the reader. Supports LZMA algorithm. Will eventually
   * support Bzip2 and Zlib. The reader offset has to be set at the beginning of the compressed data
   * before calling this function.
   * 
   * @param offset, the offset at which the compressed data can be found
   * @throws IOException
   */
  private NsisDecompressionProvider getDecompressionProvider() throws IOException {
    if ((this.firstHeader.compressedHeaderSize & FLAG_IS_COMPRESSED) != 0) {
      byte compressionByte = this.reader.peekNextByte();
      if (NsisConstants.COMPRESSION_LZMA == compressionByte) {
        this.reader.readNextByte();
        int dictionarySize = this.reader.readNextInt();
        long compressedDataLength = (this.firstHeader.compressedHeaderSize & ~FLAG_IS_COMPRESSED)
            - NsisConstants.COMPRESSION_LZMA_HEADER_LENGTH;
        ByteProvider compressedBytesProvider = new ByteProviderWrapper(
            this.reader.getByteProvider(), this.reader.getPointerIndex(), compressedDataLength);
        NsisDecompressionProvider decompressionProvider =
            new NsisLZMAProvider(compressedBytesProvider, compressionByte, dictionarySize);
        return decompressionProvider;
      } else if (NsisConstants.COMPRESSION_BZIP2 == compressionByte) {
        int compressedDataLength = this.firstHeader.compressedHeaderSize & ~FLAG_IS_COMPRESSED;
        ByteProvider compressedBytesProvider = new ByteProviderWrapper(this.reader.getByteProvider(),
            this.reader.getPointerIndex(), compressedDataLength);
        return new NsisBzipProvider(compressedBytesProvider);
      } else {
        int compressedDataLength = this.firstHeader.compressedHeaderSize & ~FLAG_IS_COMPRESSED;
        ByteProvider compressedBytesProvider = new ByteProviderWrapper(
            this.reader.getByteProvider(), this.reader.getPointerIndex(), compressedDataLength);
        return new NsisZlibProvider(compressedBytesProvider);
      }
    }
    ByteProvider uncompressedBytes = new ByteProviderWrapper(this.reader.getByteProvider(),
        this.reader.getPointerIndex(), this.firstHeader.compressedHeaderSize);
    return new NsisUncompressedProvider(uncompressedBytes);
  }

  public long getHeaderOffset() {
    return this.headerOffset;
  }

  public long getCrcOffset() {
    return this.crcSignatureOffset;
  }

  public int getInflatedHeaderSize() {
    return this.firstHeader.inflatedHeaderSize;
  }

  public int getArchiveSize() {
    return this.firstHeader.archiveSize;
  }

  public int getCompressedHeaderSize() {
    return this.firstHeader.compressedHeaderSize;
  }

  public int getScriptHeaderFlags() {
    return this.firstHeader.flags;
  }

  public int getCommonHeaderFlags() {
    return this.commonHeader.getFlags();
  }

  /**
   * Get the block header at the specified index
   * 
   * @param index
   * @return the NsisBlockHeader at that index
   */
  public NsisBlockHeader getBlockHeader(int index) {
    return this.commonHeader.getBlockHeader(index);
  }

  public InputStream getDecompressedInputStream() throws IOException {
    return this.decompressionProvider.getDecompressedStream();
  }

  /**
   * Get the offset of the given section
   * 
   * @param section
   * @return
   */
  public int getSectionOffset(NsisConstants.BlockHeaderType section) {
    return this.commonHeader.getBlockHeader(section.ordinal()).getOffset();
  }

  /**
   * Get the number of pages in the Nsis executable
   * 
   * @return the number of pages
   */
  public int getNumPages() {
    return this.pages.length;
  }

  /**
   * Get the page at the specified index
   * 
   * @param index
   * @return the corresponding NsisPage
   */
  public NsisPage getPage(int index) {
    return this.pages[index];

  }

  /**
   * Get the number of sections in the section headers part of the Nsis executable
   * 
   * @return
   */
  public int getNumSections() {
    return this.sections.length;
  }

  /**
   * Get the section from the section header at the specified index
   * 
   * @param index
   * @return
   */
  public NsisSection getSection(int index) {
    return this.sections[index];
  }

  /**
   * Get the NsisEntry from the entries section at the specified index
   * 
   * @param index
   * @return
   */
  public NsisEntry getEntry(int index) {
    return this.entries[index];
  }

  /**
   * Get the number of entries in the entries section part of the Nsis executable
   * 
   * @return
   */
  public int getNumEntries() {
    return this.entries.length;
  }

  /**
   * Get the size of the strings section of the NSIS executable
   * 
   * @return
   */
  public long getStringsSectionSize() {
    return this.strings.getStringsSectionLength();
  }

  /**
   * Get the size of the langTables section of the NSIS executable
   * 
   * @return
   */
  public long getLangTablesSectionSize() {
    return this.langTables.getLangTablesSectionLength();
  }

  /**
   * Get the size of the ctlColors section of the NSIS executable
   * 
   * @return
   */
  public long getControlColorsSectionSize() {
    return this.ctlColors.getControlColorsSectionLength();
  }

  /**
   * Get the section size from the section's start offset and the next section's start offset. If
   * the next section's start offset is 0, it calculates the size using the CRC signature offset,
   * meaning that the section is the last section of the file before the CRC bytes. If the current
   * section offset is 0, the section is not initialized so the returned size will be 0.
   * 
   * @param currentSectionStartOffset, the start offset of the section to calculate the size of
   * @param nextSectionStartOffset, the start offset of the next section. This valus should be 0 if
   *        there is no next section.
   * @return the size of the current section
   */
  private long getSectionSizeFromOffsets(int currentSectionOffset, int nextSectionOffset) {
    if (currentSectionOffset == 0) {
      return 0;
    } else if (nextSectionOffset == 0) {
      return this.firstHeader.inflatedHeaderSize - currentSectionOffset; // Last section of the file
    }
    return nextSectionOffset - currentSectionOffset;
  }

  /**
   * Get the CRC bytes of the Nsis executable
   * 
   * @return the CRC bytes
   */
  public byte[] getCrcBytes() {
    return this.crc.getBytes();
  }
}
