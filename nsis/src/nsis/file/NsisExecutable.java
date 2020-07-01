package nsis.file;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.tukaani.xz.LZMAInputStream;

import com.google.common.primitives.Bytes;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.DataType;
import nsis.format.InvalidFormatException;
import nsis.format.NsisBlockHeader;
import nsis.format.NsisScriptHeader;

/**
 * 
 * This class represents a Nsis Executable.
 *
 */
public class NsisExecutable {

	public static final String NAME = "NULLSOFT_SCRIPTABLE_INSTALLER_SYSTEM";
	public static final int FLAG_IS_COMPRESSED = 0x80000000;

	private BinaryReader reader;
	private NsisScriptHeader scriptHeader;
	private NsisBlockHeader blockHeader;
	private long headerOffset;

	/**
	 * Use createNsisExecutable to create a Nsis Executable object
	 */
	public NsisExecutable() {
	}

	/**
	 * Creates and initializes a Nsis Executable object
	 * 
	 * @param factory      that will be used to create Nsis Executable
	 * @param byteProvider object that will permit reading bytes from the file. The
	 *                     lifespan of the byte provider is controlled by Ghidra.
	 * @param layout       object used to load PE executables
	 * @return The Nsis executable object
	 * @throws IOException
	 * @throws InvalidFormatException
	 */
	public static NsisExecutable createNsisExecutable(GenericFactory factory, ByteProvider bp,
			SectionLayout layout) throws IOException, InvalidFormatException {
		NsisExecutable nsisExecutable = (NsisExecutable) factory.create(NsisExecutable.class);
		nsisExecutable.initNsisExecutable(factory, bp, layout);
		return nsisExecutable;
	}

	private void initNsisExecutable(GenericFactory factory, ByteProvider bp, SectionLayout layout)
			throws IOException, InvalidFormatException {
		this.reader = new FactoryBundledWithBinaryReader(factory, bp, /* isLittleEndian= */ true);
		this.headerOffset = findHeaderOffset();
		initScriptHeader();
		if ((this.scriptHeader.compressedHeaderSize & FLAG_IS_COMPRESSED) != 0) { // Check if MSB is
																					// set
			this.reader = new FactoryBundledWithBinaryReader(factory, decompressData(), true);
		}
		this.blockHeader = new NsisBlockHeader(this.reader);
	}

	private long findHeaderOffset() throws IOException, InvalidFormatException {
		for (long headerOffset = 0; headerOffset + NsisConstants.NSIS_SIGINFO.length
				+ NsisConstants.NSIS_MAGIC.length <= reader.length(); headerOffset++) {
			byte[] content = reader.readByteArray(headerOffset,
					NsisConstants.NSIS_SIGINFO.length + NsisConstants.NSIS_MAGIC.length);
			if (Arrays.equals(Bytes.concat(NsisConstants.NSIS_SIGINFO, NsisConstants.NSIS_MAGIC),
					content)) {
				return headerOffset - StructConverter.DWORD.getLength(); // Include flag in header
			}
		}
		throw new InvalidFormatException("Nsis magic not found.");
	}

	/**
	 * Initializes the script header.
	 * 
	 * @throws IOException
	 * @throws InvalidFormatException
	 */
	private void initScriptHeader() throws IOException, InvalidFormatException {
		this.reader.setPointerIndex(this.headerOffset);
		this.scriptHeader = new NsisScriptHeader(this.reader);
	}

	/**
	 * Attempt to decompress the data from the reader. Supports LZMA algorithm. Will
	 * eventually support Bzip2 and Zlib.
	 * 
	 * @throws IOException
	 */
	private ByteProvider decompressData() throws IOException {
		this.reader.setPointerIndex(this.headerOffset + NsisScriptHeader.getHeaderSize());
		byte compressionByte = this.reader.readNextByte();
		if (NsisConstants.COMPRESSION_LZMA == compressionByte) {
			int dictionarySize = this.reader.readNextInt();
			long compressedDataOffset = this.headerOffset + NsisScriptHeader.getHeaderSize()
					+ NsisConstants.COMPRESSION_LZMA_HEADER_LENGTH;
			// Flip the MSB to get the length
			int compressedDataLength = (this.scriptHeader.compressedHeaderSize & ~FLAG_IS_COMPRESSED)
					- NsisConstants.COMPRESSION_LZMA_HEADER_LENGTH;
			byte[] compressedData = this.reader.readByteArray(compressedDataOffset, compressedDataLength);
			LZMAInputStream lzmaInputStream = decompressLZMA(compressedData, compressionByte, dictionarySize);
			
			ByteProvider decompressedByteProvider = new InputStreamByteProvider(lzmaInputStream, 0);
			
			//return new ByteProviderWrapper(decompressedByteProvider, 0, this.scriptHeader.inflatedHeaderSize);
			return decompressedByteProvider;
		} else if (NsisConstants.COMPRESSION_BZIP2 == compressionByte) {
			// TODO Bzip2 decompress
			System.out.println("Decompress Bzip");
			return null;
		} else {// TODO find a was to identify Zlib compressed
			// TODO Zlib decompress
			System.out.println("Decompress Zlib");
			return null;
		}
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
	private LZMAInputStream decompressLZMA(byte[] compressedData, byte propByte, int dictionarySize)
			throws IOException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedData);
		LZMAInputStream lzmaInputStream = new LZMAInputStream(byteArrayInputStream, -1, propByte,
				dictionarySize);
		if(lzmaInputStream == InputStream.nullInputStream()) {
			//throw exception
		}
		return lzmaInputStream;
	}

	public long getHeaderOffset() {
		return this.headerOffset;
	}

	public int getInflatedHeaderSize() {
		return this.scriptHeader.inflatedHeaderSize;
	}

	public int getArchiveSize() {
		return this.scriptHeader.archiveSize;
	}

	public int getCompressedHeaderSize() {
		return this.scriptHeader.compressedHeaderSize;
	}

	public int getScriptHeaderFlags() {
		return this.scriptHeader.flags;
	}

	/**
	 * Returns the data structure of the Nsis Script Header.
	 * 
	 * @return a DataType object that represents the Nsis Script header
	 */
	public DataType getHeaderDataType() {
		return this.scriptHeader.toDataType();
	}
	
	public DataType getBlockHeaderDataType() {
		return this.blockHeader.toDataType();
	}
	
	public BinaryReader getBinaryReader() {
		return this.reader;
	}
}
