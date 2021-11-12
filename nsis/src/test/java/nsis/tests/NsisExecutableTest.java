package nsis.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import nsis.file.NsisConstants;
import nsis.file.NsisExecutable;
import nsis.format.InvalidFormatException;

public class NsisExecutableTest {

  private static final String pathWithoutCompression = "testData/nsis_without_compression.dat";
  private static final String pathWithBzip = "testData/nsis_with_bzip.dat";
  private static final String pathWithBzipSolid = "testData/nsis_with_bzip_solid_flag.dat";
  private static final String pathWithLzma = "testData/nsis_with_lzma.dat";
  private static final String pathWithLzmaSolid = "testData/nsis_with_lzma_solid_flag.dat";
  private static final String pathWithZlib = "testData/nsis_with_zlib.dat";
  private static final String pathWithZlibSolid = "testData/nsis_with_zlib_solid_flag.dat";

  @Test
  public void testNsisCreationNotCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithoutCompression).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x00008e00, ne.getHeaderOffset());
      assertEquals(0x00000000, ne.getScriptHeaderFlags());
      assertEquals(2046, ne.getArchiveSize());
      assertEquals(0x000007da, ne.getCompressionInfoRaw());
      assertEquals(2010, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x718,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7da,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11c, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0xb3, (byte) 0x19, (byte) 0x41, (byte) 0x44},
          ne.getCrcBytes());
    }
  }

  @Test
  public void testNsisCreationLzmaCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithLzma).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x00008800, ne.getHeaderOffset());
      assertEquals(0x00000000, ne.getScriptHeaderFlags());
      assertEquals(399, ne.getArchiveSize());
      assertEquals(0x8000016b, ne.getCompressionInfoRaw());
      assertEquals(2010, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x718,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7da,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11c, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0x83, (byte) 0x61, (byte) 0xa1, (byte) 0xaa},
          ne.getCrcBytes());
    }
  }
  
  @Test
  public void testNsisCreationLzmaSolidCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithLzmaSolid).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x8e00, ne.getHeaderOffset());
      assertEquals(0, ne.getScriptHeaderFlags());
      assertEquals(0x190, ne.getArchiveSize());
      assertEquals(0, ne.getCompressionInfoRaw());
      assertEquals(0x7dc, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x71a,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7dc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11e, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0x22, (byte) 0xf7, (byte) 0x81, (byte) 0x59},
          ne.getCrcBytes());
    }
  }

  @Test
  public void testNsisCreationZlibCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithZlib).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x00008e00, ne.getHeaderOffset());
      assertEquals(0x00000000, ne.getScriptHeaderFlags());
      assertEquals(419, ne.getArchiveSize());
      assertEquals(0x8000017f, ne.getCompressionInfoRaw());
      assertEquals(2010, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x718,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7da,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11c, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0x78, (byte) 0x88, (byte) 0x39, (byte) 0x0a},
          ne.getCrcBytes());
    }
  }
  
  @Test
  public void testNsisCreationZlibSolidCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithZlibSolid).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x9000, ne.getHeaderOffset());
      assertEquals(0, ne.getScriptHeaderFlags());
      assertEquals(0x1a7, ne.getArchiveSize());
      assertEquals(0, ne.getCompressionInfoRaw());
      assertEquals(0x7dc, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x71a,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7dc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11e, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0x95, (byte) 0xf4, (byte) 0xe8, (byte) 0x65},
          ne.getCrcBytes());
    }
  }

  @Test
  public void testNsisCreationBzipCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithBzip).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x00008a00, ne.getHeaderOffset());
      assertEquals(0x00000000, ne.getScriptHeaderFlags());
      assertEquals(463, ne.getArchiveSize());
      assertEquals(0x800001ab, ne.getCompressionInfoRaw());
      assertEquals(2010, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x718,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7da,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11c, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0x85, (byte) 0x81, (byte) 0x2e, (byte) 0xd0},
          ne.getCrcBytes());
    }
  }
  
  @Test
  public void testNsisCreationBzipSolidCompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithBzipSolid).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x8e00, ne.getHeaderOffset());
      assertEquals(0, ne.getScriptHeaderFlags());
      assertEquals(0x1cd, ne.getArchiveSize());
      assertEquals(0, ne.getCompressionInfoRaw());
      assertEquals(0x7dc, ne.getInflatedHeaderSize());

      // Header
      assertEquals(0x80, ne.getCommonHeaderFlags());
      assertEquals(0x12c,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.PAGES.ordinal()).getOffset());
      assertEquals(0x1ac,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.SECTIONS.ordinal()).getOffset());
      assertEquals(0x5c4,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.ENTRIES.ordinal()).getOffset());
      assertEquals(0x5fc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.STRINGS.ordinal()).getOffset());
      assertEquals(0x71a,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.LANGTABLES.ordinal()).getOffset());
      assertEquals(0x7dc,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.CONTROL_COLORS.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.BACKGROUND_FONT.ordinal()).getOffset());
      assertEquals(0x0,
          ne.getBlockHeader(NsisConstants.BlockHeaderType.DATA.ordinal()).getOffset());

      // Pages
      assertEquals(2, ne.getNumPages());
      assertEquals(0x6a, ne.getPage(0).getDialogResourceId());
      assertEquals(0xffffffff, ne.getPage(1).getDialogResourceId());

      // Sections
      assertEquals(1, ne.getNumSections());
      assertEquals(0x0, ne.getSection(0).getNamePtr());

      // Entries
      assertEquals(2, ne.getNumEntries());
      assertEquals(0x16, ne.getEntry(0).getOpCode());
      assertEquals(0x01, ne.getEntry(1).getOpCode());

      // Strings
      assertEquals(0x11e, ne.getStringsSectionSize());

      // LangTables
      assertEquals(0xc2, ne.getLangTablesSectionSize());

      // CtlColors
      assertEquals(0x0, ne.getControlColorsSectionSize());

      // CRC
      assertArrayEquals(new byte[] {(byte) 0x13, (byte) 0x65, (byte) 0xe1, (byte) 0x70},
          ne.getCrcBytes());
    }
  }

  /**
   * Deobfuscated the inputStream object passed as a parameter. The obfuscation is a simple XOR with
   * 0x55
   * 
   * @param inputStream
   * @return the deobfuscated ByteArrayProvider object
   * @throws IOException
   */
  private ByteArrayProvider deobfuscate(InputStream inputStream) throws IOException {
    byte[] obfuscated = inputStream.readAllBytes();
    byte[] original = new byte[obfuscated.length];
    int i = 0;
    for (byte obfuscatedByte : obfuscated) {
      original[i] = (byte) (obfuscatedByte ^ 0x55);
      i++;
    }
    return new ByteArrayProvider(original);
  }

}
