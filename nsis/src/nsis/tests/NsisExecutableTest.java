package nsis.tests;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import nsis.file.NsisExecutable;

public class NsisExecutableTest {

	private final String pathWithoutCompression = "testData/nsis_without_compression.exe";
	private final String pathWithBzip = "testData/nsis_with_bzip.exe";
	private final String pathWithLZMA = "testData/nsis_with_lzma.exe";
	private final String pathWithZlib = "testData/nsis_with_zlib.exe";

	@Test
	public void testNsisCreationNotCompressed() throws IOException {
		InputStream binaryInputStream = new FileInputStream(
				new File(pathWithoutCompression));
		ByteArrayProvider bp = new ByteArrayProvider(
				binaryInputStream.readAllBytes());
		NsisExecutable ne = NsisExecutable.createNsisExecutable(
				RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

		assertEquals((long) 36356, ne.getHeaderOffset());
		assertEquals(2046, ne.getArchiveSize());
		assertEquals(2010, ne.getCompressedHeaderSize());
		assertEquals(128, ne.getFlags());
		assertEquals(2010, ne.getInflatedHeaderSize());

		binaryInputStream.close();
	}

	@Test
	public void testNsisCreationLZMACompressed() throws IOException {
		InputStream binaryInputStream = new FileInputStream(
				new File(pathWithLZMA));
		ByteArrayProvider bp = new ByteArrayProvider(
				binaryInputStream.readAllBytes());
		NsisExecutable ne = NsisExecutable.createNsisExecutable(
				RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

		assertEquals((long) 34820, ne.getHeaderOffset());
		assertEquals(399, ne.getArchiveSize());
		assertEquals(-2147483285, ne.getCompressedHeaderSize());
		assertEquals(-2147483555, ne.getFlags());
		assertEquals(2010, ne.getInflatedHeaderSize());

		binaryInputStream.close();
	}

	@Test
	public void testNsisCreationZlibCompressed() throws IOException {
		InputStream binaryInputStream = new FileInputStream(
				new File(pathWithZlib));
		ByteArrayProvider bp = new ByteArrayProvider(
				binaryInputStream.readAllBytes());
		NsisExecutable ne = NsisExecutable.createNsisExecutable(
				RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);
		
		assertEquals((long) 36356, ne.getHeaderOffset());
		assertEquals(419, ne.getArchiveSize());
		assertEquals(-2147483265, ne.getCompressedHeaderSize());
		assertEquals(1270830573, ne.getFlags());
		assertEquals(2010, ne.getInflatedHeaderSize());

		binaryInputStream.close();
	}

	@Test
	public void testNsisCreationBzipCompressed() throws IOException {
		InputStream binaryInputStream = new FileInputStream(
				new File(pathWithBzip));
		ByteArrayProvider bp = new ByteArrayProvider(
				binaryInputStream.readAllBytes());
		NsisExecutable ne = NsisExecutable.createNsisExecutable(
				RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);
		
		assertEquals((long) 35332, ne.getHeaderOffset());
		assertEquals(463, ne.getArchiveSize());
		assertEquals(-2147483221, ne.getCompressedHeaderSize());
		assertEquals(-100597711, ne.getFlags());
		assertEquals(2010, ne.getInflatedHeaderSize());
		
		binaryInputStream.close();
	}

}
