package nsis.instructions;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;
import nsis.file.NsisConstants;

public abstract class Operation {

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

  /**
   * Resolves the arguments for a given instruction
   * 
   * @param referenceManager
   * @param instruction for which to resolve arguments
   * @param stringsBlock the MemoryBlock containing the strings
   * @param entriesBlock the MemoryBlock containing the entries
   * @throws AddressOutOfBoundsException
   * @throws MemoryAccessException
   */
  public abstract void fixUp(ReferenceManager referenceManager, Instruction instr,
      MemoryBlock stringsBlock, MemoryBlock entriesBlock)
      throws AddressOutOfBoundsException, MemoryAccessException;

}
