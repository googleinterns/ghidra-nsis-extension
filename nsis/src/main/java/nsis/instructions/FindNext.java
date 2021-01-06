package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class FindNext extends Operation {
  public static final int OPCODE = 0x3c;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {

    nsisAnalyzer.resolveVariable(instr, NsisConstants.ARGS.ARG1);
    nsisAnalyzer.resolveVariable(instr, NsisConstants.ARGS.ARG2);
  }
}
