package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import nsis.file.NsisConstants;

public class NsisSection implements StructConverter {

	private int name_ptr;
	private int install_types;
	private int flags;
	private int code;
	private int code_size;
	private int size_kb;
	private String name;

	private final static Structure STRUCTURE;

	static {
		// Values are named after the NSIS implementation of section struct:
		// https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h#l394
		STRUCTURE = new StructureDataType("Section", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "name_ptr", "initial name pointer");
		STRUCTURE.add(DWORD, DWORD.getLength(), "install_types",
				"Nbits set for each of the different install_types, if any");
		STRUCTURE.add(DWORD, DWORD.getLength(), "flags",
				"section flags (SF_*). For labels, it looks like it's only used to track how often it is used");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code",
				"The \"address\" of the start of the code in count of struct entries");
		STRUCTURE.add(DWORD, DWORD.getLength(), "code_size",
				"The size of the code in num of entries");
		STRUCTURE.add(DWORD, DWORD.getLength(), "size_kb", "Size in kb");
		STRUCTURE.add(new StringDataType(), NsisConstants.NSIS_MAX_STRLEN, "name",
				"'' for invisible sections");
	}

	public NsisSection(BinaryReader reader) throws IOException {
		this.name_ptr = reader.readNextInt();
		this.install_types = reader.readNextInt();
		this.flags = reader.readNextInt();
		this.code = reader.readNextInt();
		this.code_size = reader.readNextInt();
		this.size_kb = reader.readNextInt();
		this.name = reader.readNextAsciiString(NsisConstants.NSIS_MAX_STRLEN);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

}
