package nsis.format;

import ghidra.app.util.bin.BinaryReader;

public class NsisStrings {
  private int sectionLength;

  /**
   * When creating a NsisStrings object, the pointer of the reader is advanced to the end of the
   * strings section.
   * 
   * @param reader
   * @param sectionStartOffset
   * @param sectionEndOffset
   */
  public NsisStrings(BinaryReader reader, int sectionStartOffset, int sectionEndOffset) {
    this.sectionLength = sectionEndOffset - sectionStartOffset;
    reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
  }

  public int getStringsSectionLength() {
    return this.sectionLength;
  }
}
