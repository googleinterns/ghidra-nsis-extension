package nsis.compression;

import java.io.IOException;
import java.io.InputStream;

import org.tukaani.xz.LZMAInputStream;

import ghidra.app.util.bin.ByteProvider;

public class NsisLZMAProvider implements NsisDecompressionProvider {

	private ByteProvider byteProvider;
	private byte propertiesByte;
	private int dictionarySize;

	public NsisLZMAProvider(ByteProvider byteProvider, byte propertiesByte, int dictionarySize)
			throws IOException {
		this.byteProvider = byteProvider;
		this.propertiesByte = propertiesByte;
		this.dictionarySize = dictionarySize;
	}

	/**
	 * Decompresse LZMA bytes using a known properties byte and dictionary size.
	 * The properties byte is the first byte in the LZMA header and the dictionary
	 * size corresponds to the 4 following bytes.
	 */
	@Override
	public InputStream getDecompressedStream() throws IOException {
		LZMAInputStream lzmaInputStream = new LZMAInputStream(this.byteProvider.getInputStream(0), -1, this.propertiesByte,
				this.dictionarySize);
		if (lzmaInputStream == InputStream.nullInputStream()) {
			throw new IOException("Unable to decompress LZMA compressed data.");
		}
		return lzmaInputStream;
	}

}
