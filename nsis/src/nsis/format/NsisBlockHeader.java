package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisBlockHeader implements StructConverter {
	private int offset;
	private int num;
	private final static Structure STRUCTURE;
	
	static {
		STRUCTURE = new StructureDataType("block_header", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "offset", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "nb_entries", null);
	}
	
	
	public NsisBlockHeader(BinaryReader reader) {
		setOffset(0);
		setNum(0);

		try {
			setOffset(reader.readNextInt());
			setNum(reader.readNextInt());
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

	public int getOffset() {
		return this.offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
	}

	public int getNum() {
		return num;
	}

	public void setNum(int num) {
		this.num = num;
	}

	public static int getHeaderSize() {
		return STRUCTURE.getLength();
	}
}
