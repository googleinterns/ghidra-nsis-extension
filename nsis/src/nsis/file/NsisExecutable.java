package nsis.file;

import java.io.IOException;
import java.util.Arrays;

import com.google.common.primitives.Bytes;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.DataType;
import nsis.format.InvalidFormatException;
import nsis.format.NsisScriptHeader;

/**
 * 
 * This class represents a Nsis Executable.
 *
 */
public class NsisExecutable {

	public static final String NAME = "NULLSOFT_SCRIPTABLE_INSTALLER_SYSTEM";

	private BinaryReader reader;
	private NsisScriptHeader scriptHeader;
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
	 * @param byteProvider object that will permit reading bytes from the file.
	 *                     The lifespan of the byte provider is controlled by
	 *                     Ghidra.
	 * @param layout       object used to load PE executables
	 * @return The Nsis executable object
	 * @throws IOException
	 * @throws InvalidFormatException
	 */
	public static NsisExecutable createNsisExecutable(GenericFactory factory,
			ByteProvider bp, SectionLayout layout)
			throws IOException, InvalidFormatException {
		NsisExecutable nsisExecutable = (NsisExecutable) factory
				.create(NsisExecutable.class);
		nsisExecutable.initNsisExecutable(factory, bp, layout);
		return nsisExecutable;
	}

	private void initNsisExecutable(GenericFactory factory, ByteProvider bp,
			SectionLayout layout) throws IOException, InvalidFormatException {
		this.reader = new FactoryBundledWithBinaryReader(factory, bp,
				/* isLittleEndian= */ true);
		this.headerOffset = findHeaderOffset();
		initScriptHeader();
		if((this.scriptHeader.compressedHeaderSize & 0x80000000) != 0) {
			uncompressData();
		}
		
	}

	private long findHeaderOffset() throws IOException, InvalidFormatException {
		for (long headerOffset = 0; headerOffset
				+ NsisConstants.NSIS_SIGINFO.length + NsisConstants.NSIS_MAGIC.length <= reader
						.length(); headerOffset++) {
			byte[] content = reader.readByteArray(headerOffset,
					NsisConstants.NSIS_SIGINFO.length + NsisConstants.NSIS_MAGIC.length);
			if (Arrays.equals(Bytes.concat(NsisConstants.NSIS_SIGINFO, NsisConstants.NSIS_MAGIC), content)) {
				return headerOffset - StructConverter.DWORD.getLength(); //Include flags in header
			}
		}
		throw new InvalidFormatException("Nsis magic not found.");
	}

	private void initScriptHeader()
			throws IOException, InvalidFormatException {
		this.reader.setPointerIndex(this.headerOffset);
		this.scriptHeader = new NsisScriptHeader(this.reader);
	}
	
	private void uncompressData() throws IOException {
		byte compression = this.reader.readNextByte();
		if(isLZMA(compression)) {
			System.out.println("Decompress LZMA");
		}else if (isBzip2(compression)) {
			System.out.println("Decompress Bzip");
		}else {
			System.out.println("Decompress Zlib");
		}
		return;
	}
	
	private boolean isLZMA(byte significantByte) {
		return NsisConstants.COMPRESSION_LZMA == significantByte;
	}
	
	private boolean isBzip2(byte significantByte) {
		return NsisConstants.COMPRESSION_BZIP2 == significantByte;
	}

	public long getHeaderOffset() {
		return this.headerOffset;
	}

	public int getHeaderSize() {
		return this.scriptHeader.headerSize;
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
}
