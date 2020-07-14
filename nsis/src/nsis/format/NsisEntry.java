package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisEntry implements StructConverter{
	private final static int MAX_ENTRY_OFFSETS = 6;
	
	private int which;
	private int[] offsets = new int[MAX_ENTRY_OFFSETS];
	
	private final static Structure STRUCTURE;
	
	static {
		STRUCTURE = new StructureDataType("Entry", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "which", "EW_* enum.  Look at the enum values to see what offsets mean");
		STRUCTURE.add(new ArrayDataType(DWORD, MAX_ENTRY_OFFSETS, DWORD.getLength()), 0, "offsets", "count and meaning of offsets depend on 'which'. Sometimes they are just straight int values or bool values and sometimes they are indices into string tables.");
	}
	
	public NsisEntry(BinaryReader reader) throws IOException {
		this.which = reader.readNextInt();
		this.offsets = reader.readNextIntArray(MAX_ENTRY_OFFSETS);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

}
