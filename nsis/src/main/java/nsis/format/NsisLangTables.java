package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisLangTables implements StructConverter{
  private long sectionLength;
  public final static int LANG_TABLE_HEADER_SZ = WORD.getLength() + DWORD.getLength() + DWORD.getLength();
  public final static int LANG_TABLE_ENTRY_SZ = DWORD.getLength();
  private final static Structure LANG_TABLE_HEADER;
  
  static {
    LANG_TABLE_HEADER = new StructureDataType("Language Table Header", 0);
    LANG_TABLE_HEADER.add(WORD, WORD.getLength(), "LANGID", "Language ID eqivalent to Windows LANGID");
    LANG_TABLE_HEADER.add(DWORD, DWORD.getLength(), "dlg_offset", null);
    LANG_TABLE_HEADER.add(DWORD, DWORD.getLength(), "lang_flags", null);
  }

  private final Structure langTables;

  /**
   * When creating a NsisLangTables object, the pointer of the reader is advanced
   * to the end of the langTables section.
   * 
   * @param reader
   * @param sectionStartOffset
   * @param sectionEndOffset
   */
  public NsisLangTables(BinaryReader reader, long sectionLength, int langTableSize) {
    this.sectionLength = sectionLength;
    reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
    
    long numTables = sectionLength / langTableSize;
    long numEntries = (langTableSize - LANG_TABLE_HEADER_SZ) / LANG_TABLE_ENTRY_SZ;
    
    this.langTables = new StructureDataType("All language tables", 0);
    for(int i = 0; i< numTables; i++) {
      Structure langTable = new StructureDataType("Language table", 0);
      langTable.add(LANG_TABLE_HEADER, LANG_TABLE_HEADER.getLength(), "lang_table_header", null);
      for (int j = 0; j < numEntries; j++) {
        langTable.add(DWORD, DWORD.getLength(), String.format("entry_%x", j), null);
      }
      langTables.add(langTable, langTable.getLength(), String.format("lang_table_%x", i), null);
    }
  }

  public long getLangTablesSectionLength() {
    return this.sectionLength;
  }

  @Override
  public DataType toDataType() throws DuplicateNameException, IOException {
    return langTables;
  }
}
