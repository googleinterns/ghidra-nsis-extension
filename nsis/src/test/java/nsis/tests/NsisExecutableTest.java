package nsis.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import nsis.file.NsisConstants;
import nsis.file.NsisExecutable;
import nsis.format.InvalidFormatException;

public class NsisExecutableTest {

  private final String pathWithoutCompression = "testData/nsis_without_compression.dat";
  private final String pathWithBzip = "testData/nsis_with_bzip.dat";
  private final String pathWithLZMA = "testData/nsis_with_lzma.dat";
  private final String pathWithZlib = "testData/nsis_with_zlib.dat";

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
      assertEquals(0x000007da, ne.getCompressedHeaderSize());
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
  public void testNsisCreationLZMACompressed() throws IOException, InvalidFormatException {
    ClassLoader classLoader = getClass().getClassLoader();
    try (InputStream binaryInputStream = new FileInputStream(
        new File(classLoader.getResource(pathWithLZMA).getFile()))) {
      ByteArrayProvider bp = deobfuscate(binaryInputStream);
      NsisExecutable ne = NsisExecutable
          .createInitializeNsisExecutable(RethrowContinuesFactory.INSTANCE, bp, SectionLayout.FILE);

      // First header
      assertEquals(0x00008800, ne.getHeaderOffset());
      assertEquals(0x00000000, ne.getScriptHeaderFlags());
      assertEquals(399, ne.getArchiveSize());
      assertEquals(0x8000016b, ne.getCompressedHeaderSize());
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

  @Disabled
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
      assertEquals(0x8000017f, ne.getCompressedHeaderSize());
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

  @Disabled
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
      assertEquals(0x800001ab, ne.getCompressedHeaderSize());
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
