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
	}

	public NsisCommonHeader(BinaryReader reader) throws IOException {
		this.flags = reader.readNextInt();
		blockHeaders = new NsisBlockHeader[NsisConstants.NB_NSIS_BLOCKS];
		for (int i = 0; i < NsisConstants.NB_NSIS_BLOCKS; i++) {
			this.blockHeaders[i] = new NsisBlockHeader(reader);
		}
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
