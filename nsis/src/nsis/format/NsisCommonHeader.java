package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import nsis.file.NsisConstants;

public class NsisCommonHeader implements StructConverter {
	private int flags;
	private NsisBlockHeader[] blockHeaders;
	private int install_reg_rootkey;
	private int install_reg_key_ptr;
	private int install_reg_value_ptr;
	private int bg_color1;
	private int bg_color2;
	private int bg_textcolor;
	private int lb_bg;
	private int lb_fg;
	private int langtable_size;
	private int license_bg;
	private int code_onInit;
	private int code_onInstSuccess;
	private int code_onInstFailed;
	private int code_onUserAbort;
	private int code_onGUIInit;
	private int code_onGUIEnd;
	private int code_onMouseOverSection;
	private int code_onVerifyInstDir;
	private int code_onSelChange;
	private int code_onRebootFailed;
	private int install_types;
	private int install_directory_ptr;
	private int install_directory_auto_append;
	private int str_uninstchild;
	private int str_uninstcmd;
	private int str_wininit;

	private final static Structure STRUCTURE;

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
		STRUCTURE.add(DWORD, DWORD.getLength(), "lb_bg",
				"installation log window background color");
		STRUCTURE.add(DWORD, DWORD.getLength(), "lb_fg",
				"installation log window foreground color");
		STRUCTURE.add(DWORD, DWORD.getLength(), "langtable_size", "langtable size");
		STRUCTURE.add(DWORD, DWORD.getLength(), "license_bg", "license background color");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onInit", "code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onInstSuccess", "code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onInstFailed", "code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onUserAbort", "code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onGUIInit",
				"enhanced UI config code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onGUIEnd",
				"enhanced UI config code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onMouseOverSection",
				"enhanced UI config code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onVerifyInstDir", "code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onSelChange",
				"component page config code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_onRebootFailed",
				"reboot support code callback");
		STRUCTURE.add(DWORD, DWORD.getLength(), "install_types",
				"raw install types from component page config");
		STRUCTURE.add(DWORD, DWORD.getLength(), "install_directory_ptr",
				"default install directory");
		STRUCTURE.add(DWORD, DWORD.getLength(), "install_directory_auto_append",
				"auto append part");
		STRUCTURE.add(DWORD, DWORD.getLength(), "str_uninstchild", "uninstall support config");
		STRUCTURE.add(DWORD, DWORD.getLength(), "str_uninstcmd", "uninstall support config");
		STRUCTURE.add(DWORD, DWORD.getLength(), "str_wininit", "Points to the path of wininit.ini");
	}

	public NsisCommonHeader(BinaryReader reader) throws IOException {
		this.flags = reader.readNextInt();
		blockHeaders = new NsisBlockHeader[NsisConstants.NB_NSIS_BLOCKS];
		for (int i = 0; i < NsisConstants.NB_NSIS_BLOCKS; i++) {
			this.blockHeaders[i] = new NsisBlockHeader(reader);
		}
		this.install_reg_rootkey = reader.readNextInt();
		this.install_reg_key_ptr = reader.readNextInt();
		this.install_reg_value_ptr = reader.readNextInt();
		this.bg_color1 = reader.readNextInt();
		this.bg_color2 = reader.readNextInt();
		this.bg_textcolor = reader.readNextInt();
		this.lb_bg = reader.readNextInt();
		this.lb_fg = reader.readNextInt();
		this.langtable_size = reader.readNextInt();
		this.license_bg = reader.readNextInt();
		this.code_onInit = reader.readNextInt();
		this.code_onInstSuccess = reader.readNextInt();
		this.code_onInstFailed = reader.readNextInt();
		this.code_onUserAbort = reader.readNextInt();
		this.code_onGUIInit = reader.readNextInt();
		this.code_onGUIEnd = reader.readNextInt();
		this.code_onMouseOverSection = reader.readNextInt();
		this.code_onVerifyInstDir = reader.readNextInt();
		this.code_onSelChange = reader.readNextInt();
		this.code_onRebootFailed = reader.readNextInt();
		this.install_types = reader.readNextInt();
		this.install_directory_ptr = reader.readNextInt();
		this.install_directory_auto_append = reader.readNextInt();
		this.str_uninstchild = reader.readNextInt();
		this.str_uninstcmd = reader.readNextInt();
		this.str_wininit = reader.readNextInt();
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
