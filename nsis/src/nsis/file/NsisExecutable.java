package nsis.file;

import java.io.IOException;
import java.util.Arrays;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;

public class NsisExecutable {

	public static final String NAME = "NULLSOFT_SCRIPTABLE_INSTALLER_SYSTEM";

	private FactoryBundledWithBinaryReader reader;
	private long header_offset;

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
		this.header_offset = -1;
		findHeaderOffset();
		// TODO Init sections and headers
	}

	private void findHeaderOffset() throws IOException {
		if (this.header_offset == -1) {
			for (long offset = 0; offset
					+ NsisConstants.NSIS_MAGIC.length <= reader
							.length(); offset++) {
				byte[] content = reader.readByteArray(offset,
						NsisConstants.NSIS_MAGIC.length);
				if (Arrays.equals(NsisConstants.NSIS_MAGIC, content)) {
					this.header_offset = offset;
					return;
				}
			}
		}
	}

	public long getHeaderOffset() {
		return this.header_offset;
	}

}
