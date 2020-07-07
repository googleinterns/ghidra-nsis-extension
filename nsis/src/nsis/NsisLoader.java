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
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.PeLoader;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
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
		try {
			NsisExecutable ne = NsisExecutable.createNsisExecutable(RethrowContinuesFactory.INSTANCE, provider);
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
			NsisExecutable ne = NsisExecutable.createInitializeNsisExecutable(factory,
					provider, SectionLayout.FILE);
			long scriptHeaderOffset = ne.getHeaderOffset();

			Address scriptHeaderAddress = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(scriptHeaderOffset);

			try (InputStream headerInputStream = provider.getInputStream(scriptHeaderOffset)) {
				initScriptHeader(headerInputStream, scriptHeaderAddress, program,
						ne.getHeaderDataType(), monitor, NsisScriptHeader.getHeaderSize());
			}

			try (InputStream bodyInputStream = ne.getDecompressedInputStream()) {
				Address blockHeadersStartingAddress = scriptHeaderAddress
						.add(NsisScriptHeader.getHeaderSize());
				initBlockHeaders(bodyInputStream, blockHeadersStartingAddress, program,
						ne.getBlockHeaderDataType(), monitor, NsisBlockHeader.getHeaderSize());
			}

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
	private void initScriptHeader(InputStream is, Address scriptHeaderAddress, Program program,
			DataType dataType, TaskMonitor monitor, int size)
			throws MemoryConflictException, AddressOverflowException, CancelledException,
			DuplicateNameException, LockException, CodeUnitInsertionException {
		Memory memory = program.getMemory();
		MemoryBlock scriptHeaderBlock = memory.createInitializedBlock(".script_header",
				scriptHeaderAddress, is, size, monitor, false);
		scriptHeaderBlock.setRead(true);
		scriptHeaderBlock.setWrite(false);
		scriptHeaderBlock.setExecute(false);

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
	 * @throws CancelledException
	 * @throws CodeUnitInsertionException
	 */
	private void initBlockHeaders(InputStream is, Address startingAddr, Program program,
			DataType dataType, TaskMonitor monitor, int size)
			throws IOException, LockException, DuplicateNameException, MemoryConflictException,
			AddressOverflowException, CancelledException, CodeUnitInsertionException {
		Memory memory = program.getMemory();
		MemoryBlock blockHeadersBlock = memory.createInitializedBlock(".block_headers",
				startingAddr, is, size, monitor, false);

		blockHeadersBlock.setRead(true);
		blockHeadersBlock.setWrite(false);
		blockHeadersBlock.setExecute(false);

		int blockHeaderOffset = 0;
		// TODO add for loop for each header block in the header block list of nsis
		// executable
		Address currentBlockAddress = startingAddr.add(blockHeaderOffset);
		System.out.printf("Processing block at offset %08x\n", currentBlockAddress.getOffset());

		createData(program, currentBlockAddress, dataType);
		blockHeaderOffset += NsisBlockHeader.getHeaderSize();
	}
}
