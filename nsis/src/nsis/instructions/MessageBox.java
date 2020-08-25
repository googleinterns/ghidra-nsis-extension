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

public class MessageBox extends Operation {
  public static final int OPCODE = 0x16;

  @Override
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException {
    resolveStrings(instr, stringsBlock);
    resolveBranches(instr, entriesBlock, referenceManager);
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
    Address parameterAddr = stringsBlock.getStart().add(instr.getInt(NsisConstants.ARG2_OFFSET));
    instr.addOperandReference(NsisConstants.ARG2_INDEX, parameterAddr, RefType.PARAM,
        SourceType.ANALYSIS);
  }

  /**
   * Resolves the conditional branches
   * 
   * @param instr
   * @param entriesBlock
   * @param referenceManager
   * @throws MemoryAccessException
   */
  private void resolveBranches(Instruction instr, MemoryBlock entriesBlock,
      ReferenceManager referenceManager) throws MemoryAccessException {
    instr.setFlowOverride(FlowOverride.BRANCH);

    int arg4InstructionNumber = instr.getInt(NsisConstants.ARG4_OFFSET);

    if (arg4InstructionNumber != 0) {
      referenceManager.addMemoryReference(instr.getAddress(),
          super.getInstructionAddress(entriesBlock, arg4InstructionNumber),
          RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS, NsisConstants.ARG4_INDEX);
    }

    int arg6InstructionNumber = instr.getInt(NsisConstants.ARG6_OFFSET);
    if (arg6InstructionNumber != 0) {
      referenceManager.addMemoryReference(instr.getAddress(),
          super.getInstructionAddress(entriesBlock, arg6InstructionNumber),
          RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS, NsisConstants.ARG6_INDEX);
    }

    if (arg4InstructionNumber != 0 && arg6InstructionNumber != 0) {
      instr.setFallThrough(null);
    }

  }

}
