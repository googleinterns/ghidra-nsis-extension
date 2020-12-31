package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class StrCmp extends Operation {
  public static final int OPCODE = 0x1a;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG1);
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG2);
    // Resolve jumps
    instr.setFlowOverride(FlowOverride.BRANCH);
    int arg3InstructionNumber = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG3);
    int arg4InstructionNumber = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG4);
    if (arg3InstructionNumber != 0 && arg4InstructionNumber != 0) {
      instr.setFallThrough(null);
    }
  }
}
