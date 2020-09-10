package nsis.instructions;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import nsis.file.NsisConstants;

public class RmDir extends Operation {
  public static final int OPCODE = 0x17;

  @Override
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException {
    int filePath = instr.getInt(NsisConstants.ARG1_OFFSET);
    if (filePath != 0) {
      Address parameterAddr = stringsBlock.getStart().add(filePath);
      instr.addOperandReference(NsisConstants.ARG1_INDEX, parameterAddr, RefType.PARAM,
          SourceType.ANALYSIS);
    }
  }
}
