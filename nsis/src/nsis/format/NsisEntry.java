package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisEntry implements StructConverter{

	private final static Structure STRUCTURE;
	
	static {
		STRUCTURE = new StructureDataType("Entry", 0);
		
		
	}
	
	public NsisEntry(BinaryReader reader) {
		
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

}
