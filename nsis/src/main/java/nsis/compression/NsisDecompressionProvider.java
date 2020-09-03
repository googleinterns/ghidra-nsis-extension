package nsis.compression;

import java.io.IOException;
import java.io.InputStream;

public interface NsisDecompressionProvider {
  public InputStream getDecompressedStream() throws IOException;
}
