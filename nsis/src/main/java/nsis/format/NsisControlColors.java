package nsis.format;

import ghidra.app.util.bin.BinaryReader;

public class NsisControlColors {
  private long sectionLength;

  /**
   * When creating a NsisControlColors object, the pointer of the reader is advanced to the end of
   * the controlColors section.
   * 
   * @param reader
   * @param sectionStartOffset
   * @param sectionEndOffset
   */
  public NsisControlColors(BinaryReader reader, long sectionLength) {
    this.sectionLength = sectionLength;
    reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
  }

  public long getControlColorsSectionLength() {
    return this.sectionLength;
  }
}
