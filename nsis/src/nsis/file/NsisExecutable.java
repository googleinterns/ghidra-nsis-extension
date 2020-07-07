package nsis.file;

import java.io.IOException;
import java.util.Arrays;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
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

	private FactoryBundledWithBinaryReader reader;
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
	public static NsisExecutable createInitializeNsisExecutable(GenericFactory factory,
			ByteProvider bp, SectionLayout layout)
			throws IOException, InvalidFormatException {
		NsisExecutable nsisExecutable = NsisExecutable.createNsisExecutable(factory, bp);
		nsisExecutable.initScriptHeader(bp);
		return nsisExecutable;
	}
	
	/**
	 * Creates a Nsis Executable object, sets the reader and the offset parameter. To create and initialize a Nsis Executable object, use createInitializeNsisExecutable.
	 * @param factory
	 * @param bp
	 * @throws IOException
	 * @throws InvalidFormatException
	 */
	public static NsisExecutable createNsisExecutable(GenericFactory factory, ByteProvider bp) throws IOException, InvalidFormatException {
		NsisExecutable nsisExecutable = (NsisExecutable) factory.create(NsisExecutable.class);
		nsisExecutable.reader = new FactoryBundledWithBinaryReader(factory, bp,
				NsisConstants.IS_LITTLE_ENDIAN);
		nsisExecutable.headerOffset = nsisExecutable.findHeaderOffset();
		return nsisExecutable;
	}

	private long findHeaderOffset() throws IOException, InvalidFormatException {
		for (long headerOffset = 0; headerOffset
				+ NsisConstants.NSIS_MAGIC.length <= reader
						.length(); headerOffset++) {
			byte[] content = reader.readByteArray(headerOffset,
					NsisConstants.NSIS_MAGIC.length);
			if (Arrays.equals(NsisConstants.NSIS_MAGIC, content)) {
				return headerOffset;
			}
		}
		throw new InvalidFormatException("Nsis magic not found.");
	}

	private void initScriptHeader(ByteProvider bp)
			throws IOException, InvalidFormatException {
		BinaryReader br = new BinaryReader(bp, /* isLittleEndian= */ true);
		br.setPointerIndex(this.headerOffset);
		this.scriptHeader = new NsisScriptHeader(br);
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

	public int getFlags() {
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
