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
	public static final String firstHeaderMemoryBlockName = ".first_header";
	public static final String commonHeaderMemoryBlockName = ".common_header";
	public static final String pagesMemoryBlockName = ".pages";
	public static final String sectionsMemoryBlockName = ".section_headers";
	public static final String entriesMemoryBlockName = ".entries";
}
