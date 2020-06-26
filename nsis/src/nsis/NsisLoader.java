/* ###
 * IP:.getMe GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nsis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import nsis.file.NsisConstants;
import nsis.file.NsisExecutable;
import nsis.format.InvalidFormatException;
import nsis.format.NsisBlockHeader;
import nsis.format.NsisScriptHeader;

public class NsisLoader extends PeLoader {

	public final static String NE_NAME = "NSIS Executable (PE + NSIS)";

	@Override
	public String getName() {
		return NE_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		NsisExecutable ne;
		try {
			ne = NsisExecutable.createNsisExecutable(RethrowContinuesFactory.INSTANCE, provider,
					SectionLayout.FILE);
			LoadSpec my_spec = new LoadSpec(this, 0x400000,
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
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			NsisExecutable ne = NsisExecutable.createNsisExecutable(factory, provider,
					SectionLayout.FILE);
			long scriptHeaderOffset = ne.getHeaderOffset();
			BinaryReader binary_reader = new BinaryReader(provider, /* isLittleEndian= */ true);
			binary_reader.setPointerIndex(scriptHeaderOffset);
			Address scriptHeaderAddress = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(scriptHeaderOffset);

			FileBytes fileBytesHeader = MemoryBlockUtils.createFileBytes(program, provider,
					scriptHeaderOffset, NsisScriptHeader.getHeaderSize(), monitor);
			initScriptHeader(fileBytesHeader, scriptHeaderAddress, fileBytesHeader.getSize(),
					program, ne.getHeaderDataType());

			FileBytes fileBytesBody;
			byte[] decompressedBytes = ne.getBodyData();
			ByteArrayProvider uncompressedBytes = new ByteArrayProvider(decompressedBytes);
			fileBytesBody = MemoryBlockUtils.createFileBytes(program, uncompressedBytes, 0,
					uncompressedBytes.length(), monitor);
			initBlockHeaders(program, binary_reader,
					scriptHeaderAddress.add(NsisScriptHeader.getHeaderSize()), fileBytesBody);
		} catch (Exception e) {
			throw new IOException(e); // Ghidra handles the thrown exception
		}
	}

	/**
	 * Initializes the script header and adds it to the "Program Trees" view in
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
	private void initScriptHeader(FileBytes fileBytes, Address scriptHeaderAddress, long size,
			Program program, DataType dataType) throws MemoryConflictException,
			AddressOverflowException, CancelledException, DuplicateNameException, LockException, CodeUnitInsertionException {
		Memory memory = program.getMemory();
		MemoryBlock new_block = memory.createInitializedBlock(".script_header", scriptHeaderAddress,
				fileBytes, 0, size, false);
		new_block.setRead(true);
		new_block.setWrite(false);
		new_block.setExecute(false);

		createData(program, scriptHeaderAddress, dataType);
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
	private Data createData(Program program, Address address, DataType dt) throws CodeUnitInsertionException {
		Listing listing = program.getListing();
		Data d = listing.getDataAt(address);
		if (d == null || !dt.isEquivalent(d.getDataType())) {
			d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		return d;
	}

	/**
	 * Initializes the block headers and adds them to the "Program Trees" view in
	 * Ghidra.
	 * 
	 * @param program
	 * @param reader
	 * @param startingAddr, the Address where the nsis script header starts
	 * @throws IOException
	 * @throws AddressOverflowException
	 * @throws MemoryConflictException
	 * @throws DuplicateNameException
	 * @throws LockException
	 */
	private void initBlockHeaders(Program program, BinaryReader reader, Address startingAddr,
			FileBytes fileBytes) throws IOException, LockException, DuplicateNameException,
			MemoryConflictException, AddressOverflowException {
		int block_header_offset = 0;

		Memory memory = program.getMemory();
		MemoryBlock new_block = memory.createInitializedBlock(".block_headers", startingAddr,
				fileBytes, 0, fileBytes.getSize(), false);

		new_block.setRead(true);
		new_block.setWrite(false);
		new_block.setExecute(false);

		for (int i = 0; i < NsisConstants.NB_NSIS_BLOCKS; i++) {
			Address block_address = startingAddr.add(block_header_offset);
			System.out.printf("Processing block at offset %08x\n", block_address.getOffset());

			reader.setPointerIndex(block_address.getOffset());

			NsisBlockHeader block_header = new NsisBlockHeader(reader);
			System.out.printf("Block index: %d\n", i);
			System.out.printf("Block number of entries: %d\n", block_header.getNumEntries());
			System.out.printf("Block offset: %08x\n", block_header.getOffset());

			try {
				createData(program, block_address, block_header.toDataType());
			} catch (Exception e) {
				e.printStackTrace();
			}
			block_header_offset += NsisBlockHeader.getHeaderSize();
		}
	}
}
