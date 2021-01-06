package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;

public class Abort extends Operation {
  public static final int OPCODE = 0x3;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
  }
}
