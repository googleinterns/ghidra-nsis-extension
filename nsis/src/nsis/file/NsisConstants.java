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

	public enum Blocks {
		NB_PAGES, NB_SECTIONS, NB_ENTRIES, NB_STRINGS, NB_LANGTABLES, NB_CTLCOLORS, NB_BGFONT,
		NB_DATA, NB_BLOCKS
	}
}
