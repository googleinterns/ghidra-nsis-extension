package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import nsis.file.NsisConstants;

public class NsisCommonHeader implements StructConverter {

  private final static int INSTALL_TYPE_SIZE = NsisConstants.NSIS_MAX_INST_TYPES + 1;

  private int flags;
  private NsisBlockHeader[] blockHeaders;
  private int installRegRootkey;
  private int installRegKeyPtr;
  private int installRegValuePtr;
  private int backgroundColor1;
  private int backgroundColor2;
  private int backgroundTextcolor;
  private int instLogBackground;
  private int instLogForeground;
  private int langtableSize;
  private int licenseBackground;
  private int codeOnInit;
  private int codeOnInstSuccess;
  private int codeOnInstFailed;
  private int codeOnUserAbort;
  private int codeOnGUIInit;
  private int codeOnGUIEnd;
  private int codeOnMouseOverSection;
  private int codeOnVerifyInstDir;
  private int codeOnSelChange;
  private int codeOnRebootFailed;
  private int[] installTypes = new int[INSTALL_TYPE_SIZE];
  private int installDirectoryPtr;
  private int installDirectoryAutoAppend;
  private int strUninstChild;
  private int strUninstCmd;
  private int strWininit;

  public final static Structure STRUCTURE;

  static {
    // Values are named after the NSIS implementation of header struct:
    // https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h#l295
    STRUCTURE = new StructureDataType("Common Header", 0);
    STRUCTURE.add(DWORD, DWORD.getLength(), "flags", "Common header flags (CH_FLAGS_*)");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "pages block header", "pages block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "section block header", "section headers block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "entries block header", "entries/instructions block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "strings block header", "strings block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "language tables block header",
        "language tables (language id, dialog offset, language strings) block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "colors block header", "colors block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "bgfont block header", "bgfont block header");
    STRUCTURE.add(NsisBlockHeader.STRUCTURE, NsisBlockHeader.STRUCTURE.getLength(),
        "data block header", "data (compressed files and uninstaller data) block header");
    STRUCTURE.add(DWORD, DWORD.getLength(), "install_reg_rootkey", "InstallDirRegKey");
    STRUCTURE.add(DWORD, DWORD.getLength(), "install_reg_key_ptr", "value not processed");
    STRUCTURE.add(DWORD, DWORD.getLength(), "install_reg_value_ptr", "value not processed");
    STRUCTURE.add(DWORD, DWORD.getLength(), "bg_color1", "BGBG support");
    STRUCTURE.add(DWORD, DWORD.getLength(), "bg_color2", "BGBG support");
    STRUCTURE.add(DWORD, DWORD.getLength(), "bg_textcolor", "BGBG support");
    STRUCTURE.add(DWORD, DWORD.getLength(), "lb_bg", "installation log window background color");
    STRUCTURE.add(DWORD, DWORD.getLength(), "lb_fg", "installation log window foreground color");
    STRUCTURE.add(DWORD, DWORD.getLength(), "langtable_size", "langtable size");
    STRUCTURE.add(DWORD, DWORD.getLength(), "license_bg", "license background color");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onInit", "code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onInstSuccess", "code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onInstFailed", "code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onUserAbort", "code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onGUIInit", "enhanced UI config code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onGUIEnd", "enhanced UI config code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onMouseOverSection",
        "enhanced UI config code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onVerifyInstDir", "code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onSelChange",
        "component page config code callback");
    STRUCTURE.add(DWORD, DWORD.getLength(), "code_onRebootFailed", "reboot support code callback");
    STRUCTURE.add(new ArrayDataType(DWORD, INSTALL_TYPE_SIZE, DWORD.getLength()), 0,
        "install_types", "raw install types from component page config");
    STRUCTURE.add(DWORD, DWORD.getLength(), "install_directory_ptr", "default install directory");
    STRUCTURE.add(DWORD, DWORD.getLength(), "install_directory_auto_append", "auto append part");
    STRUCTURE.add(DWORD, DWORD.getLength(), "str_uninstchild", "uninstall support config");
    STRUCTURE.add(DWORD, DWORD.getLength(), "str_uninstcmd", "uninstall support config");
    STRUCTURE.add(DWORD, DWORD.getLength(), "str_wininit", "Points to the path of wininit.ini");
  }

  public NsisCommonHeader(BinaryReader reader) throws IOException {
    this.flags = reader.readNextInt();
    this.blockHeaders = new NsisBlockHeader[NsisConstants.BlockHeaderType.values().length];
    for (int i = 0; i < this.blockHeaders.length; i++) {
      this.blockHeaders[i] = new NsisBlockHeader(reader);
    }
    this.installRegRootkey = reader.readNextInt();
    this.installRegKeyPtr = reader.readNextInt();
    this.installRegValuePtr = reader.readNextInt();
    this.backgroundColor1 = reader.readNextInt();
    this.backgroundColor2 = reader.readNextInt();
    this.backgroundTextcolor = reader.readNextInt();
    this.instLogBackground = reader.readNextInt();
    this.instLogForeground = reader.readNextInt();
    this.langtableSize = reader.readNextInt();
    this.licenseBackground = reader.readNextInt();
    this.codeOnInit = reader.readNextInt();
    this.codeOnInstSuccess = reader.readNextInt();
    this.codeOnInstFailed = reader.readNextInt();
    this.codeOnUserAbort = reader.readNextInt();
    this.codeOnGUIInit = reader.readNextInt();
    this.codeOnGUIEnd = reader.readNextInt();
    this.codeOnMouseOverSection = reader.readNextInt();
    this.codeOnVerifyInstDir = reader.readNextInt();
    this.codeOnSelChange = reader.readNextInt();
    this.codeOnRebootFailed = reader.readNextInt();
    this.installTypes = reader.readNextIntArray(INSTALL_TYPE_SIZE);
    this.installDirectoryPtr = reader.readNextInt();
    this.installDirectoryAutoAppend = reader.readNextInt();
    this.strUninstChild = reader.readNextInt();
    this.strUninstCmd = reader.readNextInt();
    this.strWininit = reader.readNextInt();
  }

  @Override
  public DataType toDataType() {
    return STRUCTURE;
  }

  public static int getHeaderSize() {
    return STRUCTURE.getLength();
  }

  /**
   * Get the block header at the specified index
   * 
   * @param index
   * @return the NsisBlockHeader at that index
   */
  public NsisBlockHeader getBlockHeader(int index) {
    return this.blockHeaders[index];
  }

  public int getFlags() {
    return this.flags;
  }

}
