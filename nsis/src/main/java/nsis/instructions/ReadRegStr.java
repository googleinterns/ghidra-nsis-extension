package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class ReadRegStr extends Operation {
  public static final int OPCODE = 0x34;
  
  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {

    nsisAnalyzer.resolveVariable(instr, NsisConstants.ARGS.ARG1);
    nsisAnalyzer.resolveRegistryHive(instr, NsisConstants.ARGS.ARG2);
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG3);
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG4);
  }
}
