package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class NsisBlockHeader implements StructConverter {
	private int offset;
	private int numEntries;
	public final static Structure STRUCTURE;

	static {
		// Values are named after the NSIS implementation of a block header:
		// https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h#l265
		STRUCTURE = new StructureDataType("Block Header", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "offset",
				"Offset at which the block header starts");
		STRUCTURE.add(DWORD, DWORD.getLength(), "num", "Number of entries in the block header");
	}

	public NsisBlockHeader(BinaryReader reader) throws IOException {
		this.offset = reader.readNextInt();
		this.numEntries = reader.readNextInt();
	}

	@Override
	public DataType toDataType() {
		return STRUCTURE;
	}

	public int getOffset() {
		return this.offset;
	}

	public int getNumEntries() {
		return numEntries;
	}

	public static int getHeaderSize() {
		return STRUCTURE.getLength();
	}
}
