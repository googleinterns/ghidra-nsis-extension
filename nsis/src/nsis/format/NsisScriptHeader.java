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
	public final int flags;
	private byte[] siginfo;
	private byte[] magic;
	public final int headerSize;
	public final int archiveSize;
	public final int compressedHeaderSize;
	private final static Structure STRUCTURE;

	static {
		STRUCTURE = new StructureDataType("script_header", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "flags",
				"First header flags (FH_FLAGS_*)");
		STRUCTURE.add(STRING, NsisConstants.NSIS_SIGINFO.length, "siginfo",
				"0xdeadbeef (FH_SIG)");
		STRUCTURE.add(STRING, NsisConstants.NSIS_MAGIC.length, "nsinst",
				"NSIS magic (FH_INT1, FH_INT2, FH_INT3)");
		STRUCTURE.add(DWORD, DWORD.getLength(), "header_size",
				"points to the header+sections+entries+stringtable in the datablock");
		STRUCTURE.add(DWORD, DWORD.getLength(), "length_of_following_data",
				"Length of all the data (including the firstheader and the CRC)");
		STRUCTURE.add(DWORD, DWORD.getLength(), "compressed_header_size",
				"If MSB is set following data is compressed");
	}

	public NsisScriptHeader(BinaryReader reader)
			throws IOException, InvalidFormatException {
		this.flags = reader.readNextInt();
		this.siginfo = reader
				.readNextByteArray(NsisConstants.NSIS_SIGINFO.length);
		this.magic = reader.readNextByteArray(NsisConstants.NSIS_MAGIC.length);
		if (!Arrays.equals(NsisConstants.NSIS_MAGIC, this.magic)
				|| !Arrays.equals(NsisConstants.NSIS_SIGINFO, this.siginfo)) {
			throw new InvalidFormatException(
					"Invalid format. Could not find magic bytes.");
		}

		this.headerSize = reader.readNextInt();
		this.archiveSize = reader.readNextInt();
		this.compressedHeaderSize = reader.readNextInt();
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
