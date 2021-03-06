package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class MessageBox extends Operation {
  public static final int OPCODE = 0x16;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG2);
    // Resolve branckes
    instr.setFlowOverride(FlowOverride.BRANCH);
    int branchDestination1 = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG4);
    int branchDestination2 = nsisAnalyzer.resolveConditionalJump(instr, NsisConstants.ARGS.ARG6);
    if (branchDestination1 != 0 && branchDestination2 != 0) {
      instr.setFallThrough(null);
    }
  }
}
