package nsis.instructions;


import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class InstTypeSet extends Operation {
  public static final int OPCODE = 0x41;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG1);
  }
}
