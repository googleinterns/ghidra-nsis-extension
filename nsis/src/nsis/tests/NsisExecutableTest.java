package nsis.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import nsis.file.NsisExecutable;
import nsis.format.InvalidFormatException;

public class NsisExecutableTest {

	private final String pathWithoutCompression = "src/testData/nsis_without_compression.exe";
	private final String pathWithBzip = "src/testData/nsis_with_bzip.exe";
	private final String pathWithLZMA = "src/testData/nsis_with_lzma.exe";
	private final String pathWithZlib = "src/testData/nsis_with_zlib.exe";

	@Test
	public void testNsisCreationNotCompressed()
			throws IOException, InvalidFormatException {
		try (InputStream binaryInputStream = new FileInputStream(
				new File(pathWithoutCompression))) {
			ByteArrayProvider bp = new ByteArrayProvider(
					binaryInputStream.readAllBytes());
			NsisExecutable ne = NsisExecutable.createNsisExecutable(
					RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

			assertEquals(0x00008e04, ne.getHeaderOffset());
			assertEquals(2046, ne.getArchiveSize());
			assertEquals(0x000007da, ne.getCompressedHeaderSize());
			assertEquals(0x00000080, ne.getFlags());
			assertEquals(2010, ne.getHeaderSize());
		}
	}

	@Test
	public void testNsisCreationLZMACompressed()
			throws IOException, InvalidFormatException {
		try (InputStream binaryInputStream = new FileInputStream(
				new File(pathWithLZMA))) {
			ByteArrayProvider bp = new ByteArrayProvider(
					binaryInputStream.readAllBytes());
			NsisExecutable ne = NsisExecutable.createNsisExecutable(
					RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

			assertEquals(0x00008804, ne.getHeaderOffset());
			assertEquals(399, ne.getArchiveSize());
			assertEquals(0x8000016b, ne.getCompressedHeaderSize());
			assertEquals(0x8000005d, ne.getFlags());
			assertEquals(2010, ne.getHeaderSize());
		}
	}

	@Test
	public void testNsisCreationZlibCompressed()
			throws IOException, InvalidFormatException {
		try (InputStream binaryInputStream = new FileInputStream(
				new File(pathWithZlib))) {
			ByteArrayProvider bp = new ByteArrayProvider(
					binaryInputStream.readAllBytes());
			NsisExecutable ne = NsisExecutable.createNsisExecutable(
					RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

			assertEquals(0x00008e04, ne.getHeaderOffset());
			assertEquals(419, ne.getArchiveSize());
			assertEquals(0x8000017f, ne.getCompressedHeaderSize());
			assertEquals(0x4bbf55ed, ne.getFlags());
			assertEquals(2010, ne.getHeaderSize());
		}
	}

	@Test
	public void testNsisCreationBzipCompressed()
			throws IOException, InvalidFormatException {
		try (InputStream binaryInputStream = new FileInputStream(
				new File(pathWithBzip))) {
			ByteArrayProvider bp = new ByteArrayProvider(
					binaryInputStream.readAllBytes());
			NsisExecutable ne = NsisExecutable.createNsisExecutable(
					RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

			assertEquals(0x00008a04, ne.getHeaderOffset());
			assertEquals(463, ne.getArchiveSize());
			assertEquals(0x800001ab, ne.getCompressedHeaderSize());
			assertEquals(0xfa010031, ne.getFlags());
			assertEquals(2010, ne.getHeaderSize());
		}
	}

}
