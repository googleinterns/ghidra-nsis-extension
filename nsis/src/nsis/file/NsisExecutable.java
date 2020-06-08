package nsis.file;

import java.io.IOException;
import java.util.Arrays;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import nsis.format.NsisScriptHeader;

public class NsisExecutable {

	public static final String NAME = "NULLSOFT_SCRIPTABLE_INSTALLER_SYSTEM";

	private FactoryBundledWithBinaryReader reader;
	private NsisScriptHeader scriptHeader;
	private long headerOffset;

	public NsisExecutable() {
	}

	public static NsisExecutable createNsisExecutable(GenericFactory factory,
			ByteProvider bp, SectionLayout layout) throws IOException {
		NsisExecutable nsisExecutable = (NsisExecutable) factory
				.create(NsisExecutable.class);
		nsisExecutable.initNsisExecutable(factory, bp, layout);
		return nsisExecutable;
	}

	private void initNsisExecutable(GenericFactory factory, ByteProvider bp,
			SectionLayout layout) throws IOException {
		this.reader = new FactoryBundledWithBinaryReader(factory, bp, /*isLittleEndian=*/ true);
		this.headerOffset = findHeaderOffset();
		initScriptHeader(bp);
	}

	private long findHeaderOffset() throws IOException {
		long offset = -1;
		for (long testOffset = 0; testOffset
				+ NsisConstants.NSIS_MAGIC.length <= reader
						.length(); testOffset++) {
			byte[] content = reader.readByteArray(testOffset,
					NsisConstants.NSIS_MAGIC.length);
			if (Arrays.equals(NsisConstants.NSIS_MAGIC, content)) {
				offset = testOffset;
				break;
			}
		}
		return offset;
	}

	private void initScriptHeader(ByteProvider bp) throws IOException {
		BinaryReader br = new BinaryReader(bp, /*isLittleEndian=*/ true);
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

	public DataType getHeaderDataType()
			throws DuplicateNameException, IOException {
		return this.scriptHeader.toDataType();
	}
}
