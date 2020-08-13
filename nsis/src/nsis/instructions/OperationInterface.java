package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;

public interface OperationInterface {

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
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException;

}
