package nsis.compression;

import java.io.IOException;
import java.io.InputStream;

import org.tukaani.xz.LZMAInputStream;

import ghidra.app.util.bin.ByteProvider;

public class NsisLZMAProvider implements NsisDecompressionProvider {

	private LZMAInputStream decompressedStream;

	public NsisLZMAProvider(ByteProvider compressedBytesProvider, byte propertiesByte,
			int dictionarySize) throws IOException {
		InputStream compressedInputStream = compressedBytesProvider.getInputStream(0);
		this.decompressedStream = decompressLZMA(compressedInputStream, propertiesByte,
				dictionarySize);
	}

	/**
	 * Decompressed LZMA bytes using a known properties byte and dictionary size.
	 * The properties byte is the first byte in the LZMA header and the dictionary
	 * size corresponds to the 4 following bytes.
	 * 
	 * @param compressedData
	 * @param propByte       the byte indicating LZMA properties
	 * @param dictionarySize the size of the dictionary to use for decompression
	 * @throws IOException
	 */
	private LZMAInputStream decompressLZMA(InputStream compressedData, byte propByte,
			int dictionarySize) throws IOException {
		LZMAInputStream lzmaInputStream = new LZMAInputStream(compressedData, -1, propByte,
				dictionarySize);
		if (lzmaInputStream == InputStream.nullInputStream()) {
			// TODO throw exception
		}
		return lzmaInputStream;
	}

	@Override
	public InputStream getDecompressedStream() {
		return this.decompressedStream;
	}

}
