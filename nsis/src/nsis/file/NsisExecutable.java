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
		this.reader = new FactoryBundledWithBinaryReader(factory, bp, true);
		this.headerOffset = -1;
		findHeaderOffset();
		initScriptHeader(bp);
	}

	private void findHeaderOffset() throws IOException {
		if (this.headerOffset == -1) {
			for (long offset = 0; offset
					+ NsisConstants.NSIS_MAGIC.length <= reader
							.length(); offset++) {
				byte[] content = reader.readByteArray(offset,
						NsisConstants.NSIS_MAGIC.length);
				if (Arrays.equals(NsisConstants.NSIS_MAGIC, content)) {
					this.headerOffset = offset;
					return;
				}
			}
		}
	}

	private void initScriptHeader(ByteProvider bp) throws IOException {
		BinaryReader br = new BinaryReader(bp, true);
		br.setPointerIndex(this.headerOffset);
		this.scriptHeader = new NsisScriptHeader(br);
	}

	public long getHeaderOffset() {
		return this.headerOffset;
	}

	public int getInflatedHeaderSize() {
		return this.scriptHeader.getInflatedHeaderSize();
	}

	public int getArchiveSize() {
		return this.scriptHeader.getArchiveSize();
	}

	public int getCompressedHeaderSize() {
		return this.scriptHeader.getCompressedHeaderSize();
	}

	public int getFlags() {
		return this.scriptHeader.getFlags();
	}

	public DataType getHeaderDataType()
			throws DuplicateNameException, IOException {
		return this.scriptHeader.toDataType();
	}
}
