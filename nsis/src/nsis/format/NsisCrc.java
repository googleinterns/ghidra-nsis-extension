package nsis.format;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import nsis.file.NsisConstants;

public class NsisCrc {
  private byte[] crc;

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
    this.crc = reader.readNextByteArray(NsisConstants.NSIS_CRC_LENGTH);
  }

  /**
   * Get the CRC bytes
   * 
   * @return
   */
  public byte[] getCrcBytes() {
    return this.crc;
  }
}
