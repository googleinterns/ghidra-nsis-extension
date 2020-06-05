package nsis.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import nsis.file.NsisExecutable;

public class NsisExecutableTest {

	private byte[] mockFile = { (byte) 0xef, (byte) 0xef, (byte) 0xef,
			(byte) 0xbe, (byte) 0xad, (byte) 0xde, 'N', 'u', 'l', 'l', 's', 'o',
			'f', 't', 'I', 'n', 's', 't' };

	@Test
	public void testNsisCreation() throws IOException {
		ByteArrayProvider bp = new ByteArrayProvider(this.mockFile);
		NsisExecutable ne = NsisExecutable.createNsisExecutable(
				RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);
		long headerOffset = ne.getHeaderOffset();
		assertEquals((long) 3, headerOffset);
	}

}
