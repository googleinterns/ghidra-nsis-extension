package nsis.instructions;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import nsis.file.NsisConstants;

public abstract class Operation implements OperationInterface {

  /**
   * Get the address in memory associated to the position 'instruction number' in the entries block
   * 
   * @param entriesBlock, the memory block containing the instructions (entries)
   * @param instructionNumber, the instruction number for which the address is needed
   * @return the address associated to that instruction
   */
  protected Address getInstructionAddress(MemoryBlock entriesBlock, int instructionNumber) {
    long instructionOffset = (instructionNumber - 1) * NsisConstants.INSTRUCTION_BYTE_LENGTH;
    return entriesBlock.getStart().add(instructionOffset);
  }

}
