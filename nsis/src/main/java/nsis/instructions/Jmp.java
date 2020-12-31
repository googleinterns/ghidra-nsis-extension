package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class Jmp extends Operation {
  public static final int OPCODE = 0x02;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    instr.setFlowOverride(FlowOverride.BRANCH);
    nsisAnalyzer.resolveUnconditionalJump(instr, NsisConstants.ARGS.ARG1);
    instr.setFallThrough(null);
  }
}
