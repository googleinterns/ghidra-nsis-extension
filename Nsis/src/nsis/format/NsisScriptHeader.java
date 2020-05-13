package nsis.format;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import nsis.file.NsisConstants;

public class NsisScriptHeader implements StructConverter {
	private byte[] magic;
	private int inflatedHeaderSize;
	private int archiveSize;
	private int compressedHeaderSize;
	private int flags;

	public NsisScriptHeader(BinaryReader reader) throws IOException {
		setMagic(reader.readNextByteArray(NsisConstants.NSIS_MAGIC.length));
		if (!Arrays.equals(NsisConstants.NSIS_MAGIC, getMagic())) {
			throw new IOException("not a nsis file.");
		}

		setInflatedHeaderSize(reader.readNextInt());
		setArchiveSize(reader.readNextInt());
		setCompressedHeaderSize(reader.readNextInt());
		setFlags(reader.readNextInt());
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("script_header", 0);
		structure.add(STRING, NsisConstants.NSIS_MAGIC.length, "magic", null);
		structure.add(DWORD, 4, "inf_size", null);
		structure.add(DWORD, 4, "hdr_size", null);
		structure.add(DWORD, 4, "cmpr_hdr_size", null);
		structure.add(DWORD, 4, "flags", null);
		return structure;
	}

	public byte[] getMagic() {
		return magic;
	}

	public void setMagic(byte[] magic) {
		this.magic = magic;
	}

	public int getInflatedHeaderSize() {
		return inflatedHeaderSize;
	}

	public void setInflatedHeaderSize(int inflated_header_size) {
		this.inflatedHeaderSize = inflated_header_size;
	}

	public int getArchiveSize() {
		return archiveSize;
	}

	public void setArchiveSize(int archiveSize) {
		this.archiveSize = archiveSize;
	}

	public int getCompressedHeaderSize() {
		return compressedHeaderSize;
	}

	public void setCompressedHeaderSize(int compressedHeaderSize) {
		this.compressedHeaderSize = compressedHeaderSize;
	}

	public static int getHeaderSize() {
		return NsisConstants.NSIS_MAGIC.length + 4 + 4 + 4 + 4;
	}

	public int getFlags() {
		return flags;
	}

	public void setFlags(int flags) {
		this.flags = flags;
	}
}
