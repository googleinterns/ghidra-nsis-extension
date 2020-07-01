package nsis.compression;

import java.io.InputStream;

public class NsisUncompressedProvider implements NsisDecompressionProvider{
	private InputStream uncompressedInputStream;
	
	public NsisUncompressedProvider(InputStream uncompressedInputStream) {
		this.uncompressedInputStream = uncompressedInputStream;
	}
	@Override
	public InputStream getDecompressedStream() {
		return this.uncompressedInputStream;
	}

}
