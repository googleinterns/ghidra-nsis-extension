package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class PushPop extends Operation {
  public static final int OPCODE = 0x1f;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {

    int param = instr.getInt(NsisConstants.ARGS.ARG1.offset);
    int popFlag = instr.getInt(NsisConstants.ARGS.ARG2.offset);
    int exchFlag = instr.getInt(NsisConstants.ARGS.ARG3.offset);

    if (param != 0 && popFlag != 1 & exchFlag != 1) {
      String arg1Resolved = nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG1);
      nsisAnalyzer.getListing().setComment(instr.getAddress(), CodeUnit.EOL_COMMENT,
          String.format("Push %s", arg1Resolved));
    } else if (popFlag == 1) {
      String arg1Resolved = nsisAnalyzer.resolveVariable(instr, NsisConstants.ARGS.ARG1);
      nsisAnalyzer.getListing().setComment(instr.getAddress(), CodeUnit.EOL_COMMENT,
          String.format("Pop %s", arg1Resolved));
    } else if (exchFlag == 1) {
      nsisAnalyzer.getListing().setComment(instr.getAddress(), CodeUnit.EOL_COMMENT, "Exch");
    }
  }
}
