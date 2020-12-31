package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import nsis.NsisAnalyzer;
import nsis.file.NsisConstants;

public class SetFlag extends Operation {
  public static final int OPCODE = 0xd;

  @Override
  public void fixUp(Instruction instr, NsisAnalyzer nsisAnalyzer)
      throws AddressOutOfBoundsException, MemoryAccessException {
    int id = instr.getInt(NsisConstants.ARGS.ARG1.offset);
    if (NsisConstants.EXEC_FLAGS.containsKey(id)) {
      nsisAnalyzer.safeEquate(instr, NsisConstants.ARGS.ARG1,
          NsisConstants.EXEC_FLAGS.get(id), id);
    }
    
    nsisAnalyzer.resolveString(instr, NsisConstants.ARGS.ARG2);
  }
}
