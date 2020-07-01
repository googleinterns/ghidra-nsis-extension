package nsis.compression;

import java.io.InputStream;

public interface NsisDecompressionProvider {
	public InputStream getDecompressedStream();
}
