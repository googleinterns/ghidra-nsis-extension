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

public class DeleteReg extends Operation {
  public static final int OPCODE = 0x32;
  
  @Override
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException {

    int regKey = instr.getInt(NsisConstants.ARG3_OFFSET);
    if (regKey != 0) {
      Address parameterAddr = stringsBlock.getStart().add(regKey);
      instr.addOperandReference(NsisConstants.ARG3_INDEX, parameterAddr, RefType.PARAM,
          SourceType.ANALYSIS);
    }
    
    int regValue = instr.getInt(NsisConstants.ARG4_OFFSET);
    if (regValue != 0) {
      Address parameterAddr = stringsBlock.getStart().add(regValue);
      instr.addOperandReference(NsisConstants.ARG4_INDEX, parameterAddr, RefType.PARAM,
          SourceType.ANALYSIS);
    }
  }

}
