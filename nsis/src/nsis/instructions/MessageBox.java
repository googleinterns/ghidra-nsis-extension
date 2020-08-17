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

public class MessageBox extends Operation {
  public static final int OPCODE = 0x16;

  @Override
  public void fixUp(ReferenceManager referenceManager, Instruction instr, MemoryBlock stringsBlock,
      MemoryBlock entriesBlock) throws AddressOutOfBoundsException, MemoryAccessException {
    resolveStrings(instr, stringsBlock);
  }

  /**
   * Resolves the strings' offsets
   * 
   * @param instruction to add the strings to
   * @param stringsBlock the memory block where the strings are
   * @throws AddressOutOfBoundsException
   * @throws MemoryAccessException
   */
  private void resolveStrings(Instruction instr, MemoryBlock stringsBlock)
      throws AddressOutOfBoundsException, MemoryAccessException {
    Address parameterAddr = stringsBlock.getStart().add(instr.getInt(NsisConstants.ARG2_OFFSET));
    instr.addOperandReference(NsisConstants.ARG2_INDEX, parameterAddr, RefType.PARAM,
        SourceType.ANALYSIS);
  }

}
