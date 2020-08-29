package nsis.compression;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.ByteProvider;

public class NsisZlibProvider implements NsisDecompressionProvider {

  private ByteProvider byteProvider;

  public NsisZlibProvider(ByteProvider byteProvider) {
    this.byteProvider = byteProvider;
  }

  @Override
  public InputStream getDecompressedStream() throws IOException {
    return new InflaterInputStream(this.byteProvider.getInputStream(0), new Inflater(true));
  }
}
