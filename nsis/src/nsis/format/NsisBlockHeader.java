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
	private int nbEntries;
	private final static Structure STRUCTURE;

	static {
		STRUCTURE = new StructureDataType("block_header", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "offset",
				"Offset at which the block header starts");
		STRUCTURE.add(DWORD, DWORD.getLength(), "num",
				"Number of entries in the block header");
	}

	public NsisBlockHeader(BinaryReader reader) throws IOException {
		this.offset = reader.readNextInt();
		this.nbEntries = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

	public int getOffset() {
		return this.offset;
	}

	public int getNbEntries() {
		return nbEntries;
	}

	public static int getHeaderSize() {
		return STRUCTURE.getLength();
	}
}
