package nsis.file;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

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
import ghidra.util.exception.DuplicateNameException;
import nsis.compression.NsisDecompressionProvider;
import nsis.compression.NsisLZMAProvider;
import nsis.compression.NsisUncompressedProvider;
import nsis.format.InvalidFormatException;
import nsis.format.NsisBlockHeader;
import nsis.format.NsisCommonHeader;
import nsis.format.NsisFirstHeader;
import nsis.format.NsisPage;

/**
 * 
 * This class represents a Nsis Executable.
 *
 */
public class NsisExecutable {

	public static final String NAME = "NULLSOFT_SCRIPTABLE_INSTALLER_SYSTEM";
	public static final int FLAG_IS_COMPRESSED = 0x80000000;

	private BinaryReader reader;
	private NsisDecompressionProvider decompressionProvider;
	private NsisFirstHeader firstHeader;
	private NsisCommonHeader commonHeader;
	private NsisPage[] pages;
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
	public static NsisExecutable createInitializeNsisExecutable(GenericFactory factory,
			ByteProvider bp, SectionLayout layout) throws IOException, InvalidFormatException {
		NsisExecutable nsisExecutable = NsisExecutable.createNsisExecutable(factory, bp);
		nsisExecutable.initNsisExecutable(factory);
		return nsisExecutable;
	}

	/**
	 * Creates a Nsis Executable object, sets the reader and the offset parameter.
	 * To create and initialize a Nsis Executable object, use
	 * createInitializeNsisExecutable.
	 * 
	 * @param factory
	 * @param bp
	 * @throws IOException
	 * @throws InvalidFormatException
	 */
	public static NsisExecutable createNsisExecutable(GenericFactory factory, ByteProvider bp)
			throws IOException, InvalidFormatException {
		NsisExecutable nsisExecutable = (NsisExecutable) factory.create(NsisExecutable.class);
		nsisExecutable.reader = new FactoryBundledWithBinaryReader(factory, bp,
				NsisConstants.IS_LITTLE_ENDIAN);
		nsisExecutable.headerOffset = nsisExecutable.findHeaderOffset();
		return nsisExecutable;
	}

	private void initNsisExecutable(GenericFactory factory)
			throws IOException, InvalidFormatException {
		initFirstHeader();
		this.decompressionProvider = getDecompressionProvider();
		try (InputStream decompressesdStream = this.getDecompressedInputStream()) {
			ByteProvider blockDataByteProvider = new InputStreamByteProvider(decompressesdStream,
					this.firstHeader.inflatedHeaderSize);
			BinaryReader blockReader = new FactoryBundledWithBinaryReader(factory,
					blockDataByteProvider, NsisConstants.IS_LITTLE_ENDIAN);
			this.commonHeader = new NsisCommonHeader(blockReader);
			this.pages = getPages(blockReader);
		}
	}

	/**
	 * Get an array of the right amount of pages in the Nsis executable. The reader
	 * object is expected to be at the right offset (at the beginning of the first
	 * page) before calling this function.
	 * 
	 * @param reader
	 * @return NsisPage array that contains all the pages in the Nsis executable
	 * @throws IOException
	 */
	private NsisPage[] getPages(BinaryReader reader) throws IOException {
		NsisBlockHeader pagesBlockHeader = this.commonHeader.getBlockHeader(0);
		NsisPage[] pages = new NsisPage[pagesBlockHeader.getNumEntries()];
		for (int i = 0; i < pages.length; i++) {
			pages[i] = new NsisPage(reader);
		}
		return pages;
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
	private void initFirstHeader() throws IOException, InvalidFormatException {
		this.reader.setPointerIndex(this.headerOffset);
		this.firstHeader = new NsisFirstHeader(this.reader);
	}

	/**
	 * Attempt to decompress the data from the reader. Supports LZMA algorithm. Will
	 * eventually support Bzip2 and Zlib. The reader offset has to be set at the
	 * beginning of the compressed data before calling this function.
	 * 
	 * @param offset, the offset at which the compressed data can be found
	 * @throws IOException
	 */
	private NsisDecompressionProvider getDecompressionProvider() throws IOException {
		if ((this.firstHeader.compressedHeaderSize & FLAG_IS_COMPRESSED) != 0) {
			byte compressionByte = this.reader.peekNextByte();
			if (NsisConstants.COMPRESSION_LZMA == compressionByte) {
				this.reader.readNextByte();
				int dictionarySize = this.reader.readNextInt();
				long compressedDataLength = (this.firstHeader.compressedHeaderSize
						& ~FLAG_IS_COMPRESSED) - NsisConstants.COMPRESSION_LZMA_HEADER_LENGTH;
				ByteProvider compressedBytesProvider = new ByteProviderWrapper(
						this.reader.getByteProvider(), this.reader.getPointerIndex(),
						compressedDataLength);
				NsisDecompressionProvider decompressionProvider = new NsisLZMAProvider(
						compressedBytesProvider, compressionByte, dictionarySize);
				return decompressionProvider;
			} else if (NsisConstants.COMPRESSION_BZIP2 == compressionByte) {
				// TODO Bzip2 decompress
				System.out.println("Decompress Bzip");
				ByteProvider uncompressedBytes = new ByteProviderWrapper(
						this.reader.getByteProvider(), this.reader.getPointerIndex(),
						this.firstHeader.compressedHeaderSize);
				return new NsisUncompressedProvider(uncompressedBytes);
			} else {// TODO find a was to identify Zlib compressed
				// TODO Zlib decompress
				System.out.println("Decompress Zlib");
				ByteProvider uncompressedBytes = new ByteProviderWrapper(
						this.reader.getByteProvider(), this.reader.getPointerIndex(),
						this.firstHeader.compressedHeaderSize);
				return new NsisUncompressedProvider(uncompressedBytes);
			}
		}
		ByteProvider uncompressedBytes = new ByteProviderWrapper(this.reader.getByteProvider(),
				this.reader.getPointerIndex(), this.firstHeader.compressedHeaderSize);
		return new NsisUncompressedProvider(uncompressedBytes);
	}

	public long getHeaderOffset() {
		return this.headerOffset;
	}

	public int getInflatedHeaderSize() {
		return this.firstHeader.inflatedHeaderSize;
	}

	public int getArchiveSize() {
		return this.firstHeader.archiveSize;
	}

	public int getCompressedHeaderSize() {
		return this.firstHeader.compressedHeaderSize;
	}

	public int getScriptHeaderFlags() {
		return this.firstHeader.flags;
	}

	/**
	 * Returns the data structure of the Nsis Script Header.
	 * 
	 * @return a DataType object that represents the Nsis Script header
	 */
	public DataType getHeaderDataType() {
		return this.firstHeader.toDataType();
	}

	public DataType getCommonHeaderDataType() {
		return this.commonHeader.toDataType();
	}

	public int getCommonHeaderFlags() {
		return this.commonHeader.getFlags();
	}

	/**
	 * Get the block header at the specified index
	 * 
	 * @param index
	 * @return the NsisBlockHeader at that index
	 */
	public NsisBlockHeader getBlockHeader(int index) {
		return this.commonHeader.getBlockHeader(index);
	}

	public InputStream getDecompressedInputStream() throws IOException {
		return this.decompressionProvider.getDecompressedStream();
	}

	/**
	 * Get the number of pages in the Nsis executable
	 * 
	 * @return the number of pages
	 */
	public int getNumPages() {
		return this.pages.length;
	}

	/**
	 * Returns the data structure of a Nsis page
	 * 
	 * @return a DataType object that represents one Nsis page
	 * @throws DuplicateNameException
	 * @throws IOException
	 */
	public DataType getPageDataType() throws DuplicateNameException, IOException {
		return this.pages[0].toDataType();
	}

}
