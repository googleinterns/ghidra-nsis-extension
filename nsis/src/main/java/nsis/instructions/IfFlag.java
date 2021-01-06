package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class IfFlag extends Operation {
  public static final int OPCODE = 0xe;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    // Resolve jumps
    instr.setFlowOverride(FlowOverride.BRANCH);
    int arg1InstructionNumber = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG1);
    int arg2InstructionNumber = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG2);
    if (arg1InstructionNumber != 0 && arg2InstructionNumber != 0) {
      instr.setFallThrough(null);
    }
  }
}
