package nsis.instructions;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import nsis.file.NsisConstants;

public class Strcmp extends Operation {
  public static final int OPCODE = 0x1a;

  @Override
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException {
    resolveStrings(instr, stringsBlock);
    resolveBranches(instr, entriesBlock, referenceManager);
  }

  /**
   * Resolves the conditionnal branches
   * 
   * @param instr
   * @param entriesBlock
   * @param referenceManager
   * @throws MemoryAccessException
   */
  private void resolveBranches(Instruction instr, MemoryBlock entriesBlock,
      ReferenceManager referenceManager) throws MemoryAccessException {
    instr.setFlowOverride(FlowOverride.BRANCH);
    int arg3InstructionNumber = instr.getInt(NsisConstants.ARG3_OFFSET);

    if (arg3InstructionNumber != 0) {
      referenceManager.addMemoryReference(instr.getAddress(),
          super.getInstructionAddress(entriesBlock, arg3InstructionNumber),
          RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS, NsisConstants.ARG3_INDEX);
    }

    int arg4InstructionNumber = instr.getInt(NsisConstants.ARG4_OFFSET);
    if (arg4InstructionNumber != 0) {
      referenceManager.addMemoryReference(instr.getAddress(),
          super.getInstructionAddress(entriesBlock, arg4InstructionNumber),
          RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS, NsisConstants.ARG4_INDEX);
    }

    if (arg3InstructionNumber != 0 && arg4InstructionNumber != 0) {
      instr.setFallThrough(null);
    }
  }

  /**
   * Resolves the strings' offsets
   * 
   * @param instruction to add the strings to
   * @param stringsBlock the memory block where the strings are
   * @throws AddressOutOfBoundsException
   * @throws MemoryAccessException
   */
  private void resolveStrings(Instruction instr, MemoryBlock stringsBlock)
      throws AddressOutOfBoundsException, MemoryAccessException {
    Address parameterAddr = stringsBlock.getStart().add(instr.getInt(NsisConstants.ARG1_OFFSET));
    instr.addOperandReference(NsisConstants.ARG1_INDEX, parameterAddr, RefType.PARAM,
        SourceType.ANALYSIS);

    parameterAddr = stringsBlock.getStart().add(instr.getInt(NsisConstants.ARG2_OFFSET));
    instr.addOperandReference(NsisConstants.ARG2_INDEX, parameterAddr, RefType.PARAM,
        SourceType.ANALYSIS);
  }

}
