package nsis.format;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import nsis.file.NsisConstants;

public class NsisCrc implements StructConverter {
  private byte[] signature;
  public final static Structure STRUCTURE;

  static {
    STRUCTURE = new StructureDataType("CRC", 0);
    STRUCTURE.add(new ArrayDataType(BYTE, NsisConstants.NSIS_CRC_LENGTH, BYTE.getLength()), 0,
        "CRC bytes", "signature");
  }

  /**
   * Creates a NsisCrc object with the reader. The index of the reader has to already be at the
   * beginning of the CRC signature bytes before calling the constructor. The index of the reader is
   * not advanced after creating this object, because the CRC are supposed to be the last bytes of
   * the reader.
   * 
   * @param reader
   * @throws IOException
   */
  public NsisCrc(BinaryReader reader) throws IOException {
    this.signature = reader.readNextByteArray(NsisConstants.NSIS_CRC_LENGTH);
  }

  /**
   * Get the CRC bytes
   * 
   * @return
   */
  public byte[] getBytes() {
    return this.signature;
  }

  @Override
  public DataType toDataType() throws DuplicateNameException, IOException {
    return STRUCTURE;
  }
}
