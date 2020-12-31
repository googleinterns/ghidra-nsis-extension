package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;

public abstract class Operation {
  /**
   * Resolves the arguments for a given instruction
   * @param nsisAnalyzer     contains methods for updating the analysis.
   * @param instruction      for which to resolve arguments
   * 
   * @throws AddressOutOfBoundsException
   * @throws MemoryAccessException
   */
  public abstract void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException;
}
