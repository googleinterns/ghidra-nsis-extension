/* ###
 * IP: GHIDRA
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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import nsis.file.NsisConstants;

/**
 * This analyzer finds NSIS bytecode and will try to decompile it into the
 * original NSIS script.
 */
public class NsisAnalyzer extends AbstractAnalyzer {

	public NsisAnalyzer() {
		super("NSIS script decompiler", "Decompiles NSIS bytecode into NSIS script.",
				AnalyzerType.BYTE_ANALYZER);
	}

	/**
	 * Determines if the analyzer should be enabled by default
	 */
	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	/**
	 * Determines if this analyzer can analyze the given program.
	 */
	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		if (format.equals(NsisLoader.NE_NAME)) {
			return true;
		}
		return false;
	}

	/**
	 * Registers the options provided to the user for this analyzer.
	 */
	@Override
	public void registerOptions(Options options, Program program) {
	}

	/**
	 * Perform analysis when things get added to the 'program'. Return true if the
	 * analysis succeeded.
	 */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		MemoryBlock entriesBlock = program.getMemory()
				.getBlock(NsisConstants.ENTRIES_MEMORY_BLOCK_NAME);
		AddressSet modifiedAddrSet = disassembleByteCode(program, entriesBlock, monitor);

		if (modifiedAddrSet.isEmpty()) {
			return false;
		}

		MemoryBlock stringsBlock = program.getMemory()
				.getBlock(NsisConstants.STRINGS_MEMORY_BLOCK_NAME);
		InstructionIterator instructions = program.getListing().getInstructions(modifiedAddrSet,
				/* forward direction */ true);

		for (Instruction instr : instructions) {
			try {
				resolveStrings(instr, stringsBlock);
			} catch (MemoryAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return true;
	}

	/**
	 * Disassembles the byte code in the specified memory block.
	 * 
	 * @param program     to instanciate the disassembler with
	 * @param memoryBlock to perform the disassembly on
	 * @param monitor     the TaskMonitor object to monitor the operation
	 * @return the AddressSet of the disassembled instructions
	 */
	private AddressSet disassembleByteCode(Program program, MemoryBlock memoryBlock,
			TaskMonitor monitor) {
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor,
				/* Object to notify */ null);
		AddressSet entriesAddrSet = new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd());
		return disassembler.disassemble(entriesAddrSet.getMinAddress(), entriesAddrSet,
				/* follow flow */ true);
	}

	/**
	 * Resolve strings for the specified instruction.
	 * 
	 * @param instr        the instruction
	 * @param stringsBlock the memory block containing the strings
	 * @throws MemoryAccessException
	 */
	private void resolveStrings(Instruction instr, MemoryBlock stringsBlock)
			throws MemoryAccessException {

		String mnemonic = instr.getMnemonicString();
		int[] arguments = new int[NsisConstants.NUMBER_OF_PARAMETERS];
		for (int i = 0; i < NsisConstants.NUMBER_OF_PARAMETERS; i++) {
			arguments[i] = instr.getInt(Integer.BYTES * (i + 1));
		}

		switch (mnemonic) {
		case "MessageBox":
			addReferenceToString(instr, stringsBlock, arguments[1], 1);
			break;

		default:
			break;
		}
	}

	/**
	 * Adds a reference to a string on the specified parameter of an instruction.
	 * 
	 * @param instr          the related instruction
	 * @param stringsBlock   the memory block containing the strings
	 * @param stringOffset   the offset of the string in the memory block
	 * @param parameterIndex the index of the parameter to put the reference on
	 */
	private void addReferenceToString(Instruction instr, MemoryBlock stringsBlock, int stringOffset,
			int parameterIndex) {
		Address parameterAddr = stringsBlock.getStart().add(stringOffset);
		instr.addOperandReference(parameterIndex, parameterAddr, RefType.PARAM,
				SourceType.ANALYSIS);
	}

}
