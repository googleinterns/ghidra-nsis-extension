package nsis.compression;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;

public class NsisUncompressedProvider implements NsisDecompressionProvider{
	private InputStream uncompressedInputStream;
	
	public NsisUncompressedProvider(ByteProvider uncompressedByteProvider) throws IOException {
		InputStream uncompressedInputStream = uncompressedByteProvider.getInputStream(0);
		this.uncompressedInputStream = uncompressedInputStream;
	}
	@Override
	public InputStream getDecompressedStream() {
		return this.uncompressedInputStream;
	}

}
