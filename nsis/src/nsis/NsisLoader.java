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
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
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
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
			throws IOException { // TODO call super to handle PE portion of the
									// file
		List<LoadSpec> loadSpecs = new ArrayList<>();
		NsisExecutable ne;
		try {
			ne = NsisExecutable.createNsisExecutable(
					RethrowContinuesFactory.INSTANCE, provider,
					SectionLayout.FILE);
			LoadSpec my_spec = new LoadSpec(this, 0x400000,
					new LanguageCompilerSpecPair("Nsis:LE:32:default",
							"default"),
					true);
			loadSpecs.add(my_spec);
		} catch (InvalidFormatException e) {
			// Not a Nsis file, no loading spec added
			// Do nothing
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program, TaskMonitor monitor,
			MessageLog log) throws CancelledException, IOException {

		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			NsisExecutable ne = NsisExecutable.createNsisExecutable(factory,
					provider, SectionLayout.FILE);

			long nsis_header_offset = ne.getHeaderOffset();
			if (nsis_header_offset == -1) {
				System.out.print("Could not find nsis_header_offset.\n");
				return;
			}

			// TODO we probably don't need both types of readers (input
			// stream and binary reader)
			InputStream inputStream;
			inputStream = provider.getInputStream(nsis_header_offset);
			Memory mem = program.getMemory();

			BinaryReader binary_reader = new BinaryReader(provider,
					/* isLittleEndian= */ true);
			binary_reader.setPointerIndex(nsis_header_offset);

			ghidra.program.model.address.Address script_header_start = program
					.getAddressFactory().getDefaultAddressSpace()
					.getAddress(0x0);

			MemoryBlock new_block = mem.createInitializedBlock(".script_header",
					script_header_start, inputStream,
					ne.getInflatedHeaderSize(), monitor, false);
			new_block.setRead(true);
			new_block.setWrite(true);
			new_block.setExecute(true);

			createData(program, program.getListing(), script_header_start,
					ne.getHeaderDataType());
			processBlockHeaders(program, monitor, binary_reader,
					nsis_header_offset);

			System.out.printf("Done initializing block headers\n");
		} catch (Exception e) {
			System.out.print(e.getMessage());
			log.appendException(e);
		}
	}

	public Data createData(Program program, Listing listing, Address address,
			DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private void processBlockHeaders(Program program, TaskMonitor monitor,
			BinaryReader reader, long nsis_header_offset) {
		int block_header_offset = NsisScriptHeader.getHeaderSize();
		for (int i = 0; i < NsisConstants.NB_NSIS_BLOCKS; i++) {
			System.out.printf("Processing block at offset %08x\n",
					block_header_offset);
			ghidra.program.model.address.Address block_address;
			block_address = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(block_header_offset);

			reader.setPointerIndex(nsis_header_offset + block_header_offset);
			NsisBlockHeader block_header = new NsisBlockHeader(reader);
			System.out.printf("Block index: %d\n", i);
			System.out.printf("Block number of entries: %d\n",
					block_header.getNum());
			System.out.printf("Block offset: %08x\n", block_header.getOffset());

			try {
				createData(program, program.getListing(), block_address,
						block_header.toDataType());
			} catch (Exception e) {
				e.printStackTrace();
			}
			block_header_offset += NsisBlockHeader.getHeaderSize();
		}
	}
}
