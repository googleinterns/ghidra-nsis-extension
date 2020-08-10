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
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
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
				resolveControlFlow(instr, entriesBlock, program.getReferenceManager());
			} catch (MemoryAccessException e) {
				monitor.setMessage(
						"Unable to revolve parameters at instruction: " + instr.getAddressString(
								/* display mnemonic */ true, /* pad address if necessary */ true));
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
		switch (mnemonic) {
		case "MessageBox":
			Address parameterAddr = stringsBlock.getStart()
					.add(instr.getInt(NsisConstants.ARG2_OFFSET));
			instr.addOperandReference(NsisConstants.ARG2_INDEX, parameterAddr, RefType.PARAM,
					SourceType.ANALYSIS);
			break;

		default:
			break;
		}
	}

	/**
	 * Resolve the control flow for the specified instruction
	 * 
	 * @param instr        the instruction
	 * @param entriesBlock the memory block containing the instructions
	 * @param program
	 * @throws MemoryAccessException
	 */
	private void resolveControlFlow(Instruction instr, MemoryBlock entriesBlock,
			ReferenceManager referenceManager) throws MemoryAccessException {
		String mnemonic = instr.getMnemonicString();
		int instructionNumber;
		switch (mnemonic) {
		case "Call":
			instr.setFlowOverride(FlowOverride.CALL);
			instructionNumber = instr.getInt(NsisConstants.ARG1_OFFSET);
			referenceManager.addMemoryReference(instr.getAddress(),
					entriesBlock.getStart()
							.add((instructionNumber - 1) * NsisConstants.INSTRUCTION_BYTE_LENGTH),
					RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, NsisConstants.ARG1_INDEX);
			break;

		case "Jmp":
			instr.setFlowOverride(FlowOverride.BRANCH);
			instructionNumber = instr.getInt(NsisConstants.ARG1_OFFSET);
			referenceManager.addMemoryReference(instr.getAddress(),
					entriesBlock.getStart()
							.add((instructionNumber - 1) * NsisConstants.INSTRUCTION_BYTE_LENGTH),
					RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, NsisConstants.ARG1_INDEX);
			break;

		case "Return":
			instr.setFlowOverride(FlowOverride.CALL_RETURN);
			break;

		default:
			break;
		}
	}

}
