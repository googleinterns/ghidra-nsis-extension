package nsis.format;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import nsis.file.NsisConstants;

public class NsisScriptHeader implements StructConverter {
	private byte[] magic;
	public final int inflatedHeaderSize;
	public final int archiveSize;
	public final int compressedHeaderSize;
	public final int flags;
	private final static Structure STRUCTURE;

	static {
		STRUCTURE = new StructureDataType("script_header", 0);
		STRUCTURE.add(STRING, NsisConstants.NSIS_MAGIC.length, "magic", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "inflated_header_size", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "header_size", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "compressed_header_size", null);
		STRUCTURE.add(DWORD, DWORD.getLength(), "flags", null);
	}

	public NsisScriptHeader(BinaryReader reader)
			throws IOException, InvalidFormatException {
		this.magic = reader.readNextByteArray(NsisConstants.NSIS_MAGIC.length);
		if (!Arrays.equals(NsisConstants.NSIS_MAGIC, getMagic())) {
			throw new InvalidFormatException(
					"Invalid format. Could not find magic bytes.");
		}

		this.inflatedHeaderSize = reader.readNextInt();
		this.archiveSize = reader.readNextInt();
		this.compressedHeaderSize = reader.readNextInt();
		this.flags = reader.readNextInt();
		checkHeaderCompression(reader);
	}

	@Override
	public DataType toDataType() {
		return STRUCTURE;
	}

	public byte[] getMagic() {
		return magic;
	}

	public static int getHeaderSize() {
		return STRUCTURE.getLength();
	}

	public void checkHeaderCompression(BinaryReader reader) {
		// TODO reimplement this function to throw invalidformat error when
		// necessary and fix compression identification bug
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
