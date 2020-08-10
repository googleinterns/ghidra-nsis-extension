package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisEntry implements StructConverter {
  private final static int MAX_ENTRY_OFFSETS = 6;

  private int opCode;
  private int[] parametersOffsets = new int[MAX_ENTRY_OFFSETS];

  public final static Structure STRUCTURE;

  static {
    // Values are named after the NSIS implementation of entry struct:
    // https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h#l408
    // Each entry corresponds to an instruction
    STRUCTURE = new StructureDataType("Entry", 0);
    STRUCTURE.add(DWORD, DWORD.getLength(), "which",
        "EW_* enum.  Look at the enum values to see what offsets mean");
    STRUCTURE.add(new ArrayDataType(DWORD, MAX_ENTRY_OFFSETS, DWORD.getLength()), 0, "offsets",
        "count and meaning of offsets depend on 'which'."
            + " Sometimes they are just straight int values or bool values and sometimes they are "
            + "indices into string tables.");
  }

  public NsisEntry(BinaryReader reader) throws IOException {
    this.opCode = reader.readNextInt();
    this.parametersOffsets = reader.readNextIntArray(MAX_ENTRY_OFFSETS);
  }

  @Override
  public DataType toDataType() throws DuplicateNameException, IOException {
    return STRUCTURE;
  }

  /**
   * Get the size of the Entry structure
   * 
   * @return
   */
  public static int getEntrySize() {
    return STRUCTURE.getLength();
  }

  /**
   * Get the opcode of the entry
   * 
   * @return
   */
  public int getOpCode() {
    return this.opCode;
  }

}
