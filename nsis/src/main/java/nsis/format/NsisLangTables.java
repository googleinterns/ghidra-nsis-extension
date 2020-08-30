package nsis.format;

import ghidra.app.util.bin.BinaryReader;

public class NsisLangTables {
  private long sectionLength;

  /**
   * When creating a NsisLangTables object, the pointer of the reader is advanced to the end of the
   * langTables section.
   * 
   * @param reader
   * @param sectionStartOffset
   * @param sectionEndOffset
   */
  public NsisLangTables(BinaryReader reader, long sectionLength) {
    this.sectionLength = sectionLength;
    reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
  }

  public long getLangTablesSectionLength() {
    return this.sectionLength;
  }
}
