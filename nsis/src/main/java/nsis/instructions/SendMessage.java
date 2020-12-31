package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class SendMessage extends Operation {
  public static final int OPCODE = 0x21;
  private static final int WPARAM_STRING = 0x1;
  private static final int LPARAM_STRING = 0x2;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {

    nsisAnalyzer.resolveString(instr,  NsisConstants.ARGS.ARG2);
    
    int msg = instr.getInt(NsisConstants.ARGS.ARG3.offset);

    String raw = nsisAnalyzer.buildString(msg);
    int msgVal = Integer.decode(raw);
    if (NsisConstants.WIN_MESSAGES.containsKey(msgVal)) {
      nsisAnalyzer.safeEquate(instr, NsisConstants.ARGS.ARG3,
          NsisConstants.WIN_MESSAGES.get(msgVal), msg);
    }

    int arg6 = instr.getInt(NsisConstants.ARGS.ARG6.offset);

    if ((arg6 & WPARAM_STRING) != 0) {
      nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG4);
    }
    if ((arg6 & LPARAM_STRING) != 0) {
      nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG5);
    }
  }
}
