package nsis.format;

import ghidra.app.util.bin.BinaryReader;

public class NsisStrings {
  private long sectionLength;

  /**
   * When creating a NsisStrings object, the pointer of the reader is advanced to the end of the
   * strings section.
   * 
   * @param reader
   * @param sectionStartOffset
   * @param sectionEndOffset
   */
  public NsisStrings(BinaryReader reader, long sectionLength) {
    this.sectionLength = sectionLength;
    reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
  }

  public long getStringsSectionLength() {
    return this.sectionLength;
  }
}
