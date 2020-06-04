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
	private static Structure STRUCTURE;

	public NsisScriptHeader(BinaryReader reader) throws IOException {
		this.magic = reader.readNextByteArray(NsisConstants.NSIS_MAGIC.length);
		if (!Arrays.equals(NsisConstants.NSIS_MAGIC, getMagic())) {
			throw new IOException("Not a nsis file.");
		}

		this.inflatedHeaderSize = reader.readNextInt();
		this.archiveSize = reader.readNextInt();
		this.compressedHeaderSize = reader.readNextInt();
		this.flags = reader.readNextInt();
		initStructure();
		checkHeaderCompression(reader);
	}

	private static void initStructure() {
		STRUCTURE = new StructureDataType("script_header", 0);
		STRUCTURE.add(STRING, NsisConstants.NSIS_MAGIC.length, "magic", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "inf_size", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "hdr_size", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "cmpr_hdr_size", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "flags", null);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

	public byte[] getMagic() {
		return magic;
	}

	public int getInflatedHeaderSize() {
		return inflatedHeaderSize;
	}

	public int getArchiveSize() {
		return archiveSize;
	}

	public int getCompressedHeaderSize() {
		return compressedHeaderSize;
	}

	public static int getHeaderSize() {
		return STRUCTURE.getLength();
	}

	public int getFlags() {
		return flags;
	}

	public void checkHeaderCompression(BinaryReader reader) {
		if ((this.compressedHeaderSize & 0x80000000) == 0) {
			System.out.print("Header is not compressed!\n");
			return;
		}

		int firstByte = 0;
		try {
			firstByte = reader.readByte(0);
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}

		if (firstByte == NsisConstants.COMPRESSION_LZMA) {
			System.out.print("Header is LZMA compressed\n");
		}

		if (firstByte == NsisConstants.COMPRESSION_BZIP2) {
			System.out.print("Header is BZip2 compressed\n");
		}

		System.out.print("Header is Zlib compressed\n");
	}
}
