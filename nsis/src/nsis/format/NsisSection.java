package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisSection implements StructConverter {
	
	private static final int NSIS_MAX_STRLEN = 1024;
	
	private int name_ptr;
	private int install_types;
	private int flags;
	private int code;
	private int code_size;
	private int size_kb;
	private String name;
	
	private final static Structure STRUCTURE;
	
	static {
		// Values are named after the NSIS implementation of sectopm struct:
				// https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h#l394
		STRUCTURE = new StructureDataType("Section", 0);
		
	}
	
	public NsisSection(BinaryReader reader) throws IOException {
		this.name_ptr = reader.readNextInt();
		this.install_types = reader.readNextInt();
		this.flags = reader.readNextInt();
		this.code = reader.readNextInt();
		this.code_size = reader.readNextInt();
		this.size_kb = reader.readNextInt();
		this.name = reader.readNextAsciiString(NSIS_MAX_STRLEN);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

}
