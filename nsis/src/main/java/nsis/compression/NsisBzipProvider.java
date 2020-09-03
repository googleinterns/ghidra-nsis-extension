package nsis.compression;

import java.io.IOException;
import java.io.InputStream;

import nsis.compression.bzip2.BZip2NsisInputStream;

import ghidra.app.util.bin.ByteProvider;

public class NsisBzipProvider implements NsisDecompressionProvider {

  private ByteProvider byteProvider;

  public NsisBzipProvider(ByteProvider byteProvider) {
    this.byteProvider = byteProvider;
  }

  @Override
  public InputStream getDecompressedStream() throws IOException {
    return new BZip2NsisInputStream(this.byteProvider.getInputStream(0));
  }

}
