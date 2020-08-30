package nsis.instructions;

import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import nsis.file.NsisConstants;

public class Call extends Operation {
  public static final int OPCODE = 0x05;

  @Override
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException {
    instr.setFlowOverride(FlowOverride.CALL);
    int instructionNumber = instr.getInt(NsisConstants.ARG1_OFFSET);
    referenceManager.addMemoryReference(instr.getAddress(),
        super.getInstructionAddress(entriesBlock, instructionNumber), RefType.UNCONDITIONAL_CALL,
        SourceType.ANALYSIS, NsisConstants.ARG1_INDEX);
  }

}
