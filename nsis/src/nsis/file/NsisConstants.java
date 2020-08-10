package nsis.file;

public class NsisConstants {
	public static final boolean IS_LITTLE_ENDIAN = true;
	public static final byte[] NSIS_SIGINFO = { (byte) 0xef, (byte) 0xbe, (byte) 0xad,
			(byte) 0xde };
	public static final byte[] NSIS_MAGIC = { 'N', 'u', 'l', 'l', 's', 'o', 'f', 't', 'I', 'n', 's',
			't' };
	public static final int NSIS_MAX_STRLEN = 1024;
	public static final int NSIS_MAX_INST_TYPES = 32;
	public static final byte COMPRESSION_LZMA = 0x5d;
	public static final byte COMPRESSION_BZIP2 = 0x31;
	public static final int COMPRESSION_LZMA_HEADER_LENGTH = 5;

	// The order of the blocks is important as their ordinal value corresponds to
	// their position in the NsisCommonHeader
	public enum BlockHeaderType {
		PAGES, SECTIONS, ENTRIES, STRINGS, LANGTABLES, CONTROL_COLORS, BACKGROUND_FONT, DATA
	}

	// Ghidra memory block names
	public static final String FIRST_HEADER_MEMORY_BLOCK_NAME = ".first_header";
	public static final String COMMON_HEADER_MEMORY_BLOCK_NAME = ".common_header";
	public static final String PAGES_MEMORY_BLOCK_NAME = ".pages";
	public static final String SECTIONS_MEMORY_BLOCK_NAME = ".section_headers";
	public static final String ENTRIES_MEMORY_BLOCK_NAME = ".entries";
	public static final String STRINGS_MEMORY_BLOCK_NAME = ".strings";

	// NSIS instruction constants
	public static final int NUMBER_OF_PARAMETERS = 6;
	public static final int ARG1_INDEX = 0;
	public static final int ARG2_INDEX = 1;
	public static final int ARG3_INDEX = 2;
	public static final int ARG4_INDEX = 3;
	public static final int ARG5_INDEX = 4;
	public static final int ARG6_INDEX = 5;
	public static final int ARG1_OFFSET = 4;
	public static final int ARG2_OFFSET = 8;
	public static final int ARG3_OFFSET = 12;
	public static final int ARG4_OFFSET = 16;
	public static final int ARG5_OFFSET = 20;
	public static final int ARG6_OFFSET = 24;

}
