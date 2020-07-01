package nsis.file;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import com.google.common.primitives.Bytes;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.DataType;
import nsis.compression.NsisDecompressionProvider;
import nsis.compression.NsisLZMAProvider;
import nsis.compression.NsisUncompressedProvider;
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
		this.reader = new FactoryBundledWithBinaryReader(factory, bp,
				NsisConstants.IS_LITTLE_ENDIAN);
		this.headerOffset = findHeaderOffset();
		initScriptHeader();
		NsisDecompressionProvider decompressionProvider = decompressData(
				this.headerOffset + NsisScriptHeader.getHeaderSize());
		InputStreamByteProvider inputStreamByteProvider = new InputStreamByteProvider(
				decompressionProvider.getDecompressedStream(), this.getInflatedHeaderSize());
		this.reader = new FactoryBundledWithBinaryReader(factory, inputStreamByteProvider,
				NsisConstants.IS_LITTLE_ENDIAN);
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
	 * @param offset, the offset at which the compressed data can be found
	 * @throws IOException
	 */
	private NsisDecompressionProvider decompressData(long offset) throws IOException {
		InputStream compressedInputStream = this.reader.getByteProvider().getInputStream(offset);
		if ((this.scriptHeader.compressedHeaderSize & FLAG_IS_COMPRESSED) != 0) { // Check if MSB is
			// set
			this.reader.setPointerIndex(offset);
			byte compressionByte = this.reader.readNextByte();
			if (NsisConstants.COMPRESSION_LZMA == compressionByte) {
				int dictionarySize = this.reader.readNextInt();
				compressedInputStream.skip(NsisConstants.COMPRESSION_LZMA_HEADER_LENGTH);
				NsisDecompressionProvider decompressionProvider = new NsisLZMAProvider(
						compressedInputStream, compressionByte, dictionarySize);
				return decompressionProvider;
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
		return new NsisUncompressedProvider(compressedInputStream);
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

	public InputStreamByteProvider getInputStreamByteProvider() {
		return (InputStreamByteProvider) this.reader.getByteProvider();
	}
}
