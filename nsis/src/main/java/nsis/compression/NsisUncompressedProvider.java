package nsis.compression;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;

public class NsisUncompressedProvider implements NsisDecompressionProvider {
  private ByteProvider byteProvider;

  public NsisUncompressedProvider(ByteProvider uncompressedByteProvider) throws IOException {
    this.byteProvider = uncompressedByteProvider;
  }

  @Override
  public InputStream getDecompressedStream() throws IOException {
    return this.byteProvider.getInputStream(0);
  }

}
