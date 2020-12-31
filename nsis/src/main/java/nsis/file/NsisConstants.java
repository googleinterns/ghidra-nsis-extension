package nsis.file;

import java.util.HashMap;
import java.util.Map;

public class NsisConstants {
  public static final boolean IS_LITTLE_ENDIAN = true;
  public static final byte[] NSIS_SIGINFO = { (byte) 0xef, (byte) 0xbe, (byte) 0xad, (byte) 0xde };
  public static final byte[] NSIS_MAGIC = { 'N', 'u', 'l', 'l', 's', 'o', 'f', 't', 'I', 'n', 's',
      't' };
  public static final int NSIS_MAX_STRLEN = 1024;
  public static final int NSIS_MAX_INST_TYPES = 32;
  public static final int NSIS_CRC_LENGTH = 4;

  // The order of the blocks is important as their ordinal value corresponds to
  // their position in the NsisCommonHeader
  public enum BlockHeaderType {
    PAGES, SECTIONS, ENTRIES, STRINGS, LANGTABLES, CONTROL_COLORS, BACKGROUND_FONT, DATA
  }

  // Compression related constants
  public static final byte COMPRESSION_LZMA = 0x5d;
  public static final byte COMPRESSION_BZIP2 = 0x31;
  public static final int COMPRESSION_LZMA_HEADER_LENGTH = 5;

  // Ghidra memory block names
  public static final String FIRST_HEADER_MEMORY_BLOCK_NAME = ".first_header";
  public static final String COMMON_HEADER_MEMORY_BLOCK_NAME = ".common_header";
  public static final String PAGES_MEMORY_BLOCK_NAME = ".pages";
  public static final String SECTIONS_MEMORY_BLOCK_NAME = ".section_headers";
  public static final String ENTRIES_MEMORY_BLOCK_NAME = ".entries";
  public static final String STRINGS_MEMORY_BLOCK_NAME = ".strings";
  public static final String LANGTABLES_MEMORY_BLOCK_NAME = ".langtables";
  public static final String CONTROL_COLORS_MEMORY_BLOCK_NAME = ".ctlcolors";
  public static final String CRC_SIGNATURE_MEMORY_BLOCK_NAME = ".crc";

  public static final int NS_LANG_CODE = 1;
  public static final int NS_SHELL_CODE = 2;
  public static final int NS_VAR_CODE = 3;
  public static final int NS_SKIP_CODE = 4;

  // NSIS instruction constants
  public static final int INSTRUCTION_BYTE_LENGTH = 0x1c;
  public static final int NUMBER_OF_PARAMETERS = 6;
  public static final int USER_VARIABLE_BEGIN = 0x20; // 32

  public enum ARGS {
    ARG1(0, 4), ARG2(1, 8), ARG3(2, 12), ARG4(3, 16), ARG5(4, 20), ARG6(5, 24);

    public final int index;
    public final int offset;

    ARGS(int index, int offset) {
      this.index = index;
      this.offset = offset;
    }
  }

  public static final Map<Integer, String> USER_VAR_NAMES;
  static {
    USER_VAR_NAMES = new HashMap<Integer, String>();
    USER_VAR_NAMES.put(0x14, "$CMDLINE"); // 20"
    USER_VAR_NAMES.put(0x15, "$INSTDIR"); // 21
    USER_VAR_NAMES.put(0x16, "$OUTDIR"); // 22"
    USER_VAR_NAMES.put(0x17, "$EXEDIR"); // 23"
    USER_VAR_NAMES.put(0x18, "$LANGUAGE"); // 24"
    USER_VAR_NAMES.put(0x19, "$TEMP"); // 25"
    USER_VAR_NAMES.put(0x1a, "$PLUGINSDIR"); // 26"
    USER_VAR_NAMES.put(0x1b, "$EXEPATH"); // 27"
    USER_VAR_NAMES.put(0x1c, "$EXEFILE"); // 28"
    USER_VAR_NAMES.put(0x1d, "$HWNDPARENT"); // 29"
    USER_VAR_NAMES.put(0x1e, "$_CLICK"); // 30"
    USER_VAR_NAMES.put(0x1f, "$_OUTDIR"); // 31"
  }

  public static final Map<Integer, String> REG_HIVES;
  static {
    REG_HIVES = new HashMap<Integer, String>();
    REG_HIVES.put(0x80000000, "HKEY_CLASSES_ROOT");
    REG_HIVES.put(0x80000001, "HKEY_CURRENT_USER");
    REG_HIVES.put(0x80000002, "HKEY_LOCAL_MACHINE");
    REG_HIVES.put(0x80000003, "HKEY_USERS");
    REG_HIVES.put(0x80000004, "HKEY_PERFORMANCE_DATA");
    REG_HIVES.put(0x80000005, "HKEY_CURRENT_CONFIG");
    REG_HIVES.put(0x80000006, "HKEY_DYN_DATA");
    REG_HIVES.put(0x80000050, "HKEY_PERFORMANCE_TEXT");
    REG_HIVES.put(0x80000060, "HKEY_PERFORMANCE_NLSTEXT");
  }

  public static final Map<Integer, String> USER_SHELL;
  static {
    USER_SHELL = new HashMap<Integer, String>();
    USER_SHELL.put(0x1a, "$APPDATA");
    USER_SHELL.put(0x23, "$APPDATA");
  }

  public static final Map<Integer, String> WIN_MESSAGES;
  static {
    WIN_MESSAGES = new HashMap<Integer, String>();
    WIN_MESSAGES.put(0xc, "WM_SETTEXT");
    WIN_MESSAGES.put(0x30, "WM_SETFONT");
  }

  public static final Map<Integer, String> OP_CODES;
  static {
    OP_CODES = new HashMap<Integer, String>();
    OP_CODES.put(0x0, "ADD");
    OP_CODES.put(0x1, "SUB");
    OP_CODES.put(0x2, "MUL");
    OP_CODES.put(0x3, "DIV");
    OP_CODES.put(0x4, "BOR");
    OP_CODES.put(0x5, "BAND");
    OP_CODES.put(0x6, "BXOR");
    OP_CODES.put(0x7, "BNOT");
    OP_CODES.put(0x8, "LOR");
    OP_CODES.put(0x9, "LAND");
    OP_CODES.put(0xa, "MOD");
    OP_CODES.put(0xb, "SHL");
    OP_CODES.put(0xc, "SAR");
    OP_CODES.put(0xd, "SHR");
  }

  public static final Map<Integer, String> EXEC_FLAGS;
  static {
    EXEC_FLAGS = new HashMap<Integer, String>();
    EXEC_FLAGS.put(0x0, "SetAutoClose");
    EXEC_FLAGS.put(0x1, "SetShellVarContext");
    EXEC_FLAGS.put(0x2, "IfErrors/ClearErrors/SetErrors");
    EXEC_FLAGS.put(0x3, "IfAbort");
    EXEC_FLAGS.put(0x4, "IfRebootFlag/SetRebootFlag");
    EXEC_FLAGS.put(0x5, "NSIS_SUPPORT_REBOOT");
    EXEC_FLAGS.put(0x6, "XXX_cur_insttype_DEPRECATED");
    EXEC_FLAGS.put(0x7, "See_NSISPIAPIVER_CURR");
    EXEC_FLAGS.put(0x8, "IfSilent/SetSilent");
    EXEC_FLAGS.put(0x9, "GetInstDirError");
    EXEC_FLAGS.put(0xa, "IfRtlLanguage");
    EXEC_FLAGS.put(0xb, "SetErrorLevel");
    EXEC_FLAGS.put(0xc, "SetRegView");
    EXEC_FLAGS.put(0xd, "SetDetailsPrint");
  }
  
  public static final Map<Integer, String> CHAR_ESCAPES;
  static {
    CHAR_ESCAPES = new HashMap<Integer, String>();
    CHAR_ESCAPES.put(0x9, "$\\t");
    CHAR_ESCAPES.put(0xa, "$\\n");
    CHAR_ESCAPES.put(0xd, "$\\r");
    CHAR_ESCAPES.put(0x22, "$\\");
    CHAR_ESCAPES.put(0x24, "$$");
  }
}
