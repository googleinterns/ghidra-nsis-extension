package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class IsWindow extends Operation {
  public static final int OPCODE = 0x22;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG1);
    // Resolve jumps
    instr.setFlowOverride(FlowOverride.BRANCH);
    int arg2InstructionNumber = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG2);
    int arg3InstructionNumber = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG3);
    if (arg2InstructionNumber != 0 && arg3InstructionNumber != 0) {
      instr.setFallThrough(null);
    }
  }
}
