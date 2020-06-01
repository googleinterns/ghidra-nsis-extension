package nsis.file;

public class NsisConstants {
	public static final byte[] NSIS_MAGIC = { (byte) 0xef, (byte) 0xbe,
			(byte) 0xad, (byte) 0xde, 'N', 'u', 'l', 'l', 's', 'o', 'f', 't',
			'I', 'n', 's', 't' };
	public static final int NB_NSIS_BLOCKS = 8;
}
