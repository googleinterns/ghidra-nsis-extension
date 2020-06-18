package nsis.file;

public class NsisConstants {
	public static final byte[] NSIS_SIGINFO = { (byte) 0xef, (byte) 0xbe,
			(byte) 0xad, (byte) 0xde };
	public static final byte[] NSIS_MAGIC = { 'N', 'u', 'l', 'l', 's', 'o', 'f',
			't', 'I', 'n', 's', 't' };
	public static final int NB_NSIS_BLOCKS = 8;
	public static final byte COMPRESSION_LZMA = 0x5d;
	public static final byte COMPRESSION_BZIP2 = 0x31;

}
