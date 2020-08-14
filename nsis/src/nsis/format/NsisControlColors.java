package nsis.format;

import ghidra.app.util.bin.BinaryReader;

public class NsisControlColors {
  private int sectionLength;

  /**
   * When creating a NsisControlColors object, the pointer of the reader is advanced to the end of
   * the controlColors section.
   * 
   * @param reader
   * @param sectionStartOffset
   * @param sectionEndOffset
   */
  public NsisControlColors(BinaryReader reader, int sectionStartOffset, int sectionEndOffset) {
    this.sectionLength = Math.abs(sectionEndOffset - sectionStartOffset);
    reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
  }

  public int getControlColorsSectionLength() {
    return this.sectionLength;
  }
}
