package nsis.compression.bzip2;

import java.io.IOException;
import java.io.InputStream;

/**
 * The Bzip2 implementation in NSIS has been altered from the more widely
 * distributed Bzip2 library. Based on the commit messages in the NSIS source it
 * seems that the NSIS developers desired to make the Bzip2 compressed stream
 * smaller by removing the Bzip2 header as well as the CRC check from Bzip2
 * blocks and the entire Bzip2 compressed data stream. The core compression
 * implementation of Bzip2 was not changed.
 * 
 * To account for this, the decompression parts of the Java Bzip2 library
 * https://github.com/wattsight/bzip2 were copied here and altered to behave
 * like the NSIS implementation.
 * 
 * Only the decompression parts of the library were copied, not the compression
 * parts of the library.
 * 
 * @author rossgibb
 *
 */
public class BZip2NsisInputStream extends BZip2InputStream {

  public BZip2NsisInputStream(InputStream inputStream) {
    super(inputStream, false);
  }

  @Override
  protected boolean initialiseNextBlock() throws IOException {
    /* If we're already at the end of the stream, do nothing */
    if (this.streamComplete) {
      return false;
    }

    final int marker = this.bitInputStream.readBits(8);

    if (marker == BZip2Constants.NSIS_BLOCK_HEADER_MARKER) {
      // Initialise a new block
      try {
        this.blockDecompressor = new BZip2NsisBlockDecompressor(this.bitInputStream,
            this.streamBlockSize);
      } catch (IOException e) {
        // If the block could not be decoded, stop trying to read more data
        this.streamComplete = true;
        throw e;
      }
      return true;
    } else if (marker == BZip2Constants.NSIS_STREAM_END_MARKER) {
      this.streamComplete = true;
      return false;
    }

    /*
     * If what was read is not a valid block-header or end-of-stream marker, the
     * stream is broken
     */
    this.streamComplete = true;
    throw new BZip2Exception("BZip2 stream format error");
  }

  @Override
  public int read() throws IOException {
    int nextByte = -1;
    if (this.blockDecompressor == null) {
      this.streamBlockSize = BZip2Constants.NSIS_BLOCK_SIZE;
    } else {
      nextByte = this.blockDecompressor.read();
    }

    if (nextByte == -1) {
      if (initialiseNextBlock()) {
        nextByte = this.blockDecompressor.read();
      }
    }

    return nextByte;
  }

  @Override
  public int read(byte[] destination, int offset, int length) throws IOException {
    int bytesRead = -1;
    if (this.blockDecompressor == null) {
      this.streamBlockSize = BZip2Constants.NSIS_BLOCK_SIZE;
    } else {
      bytesRead = this.blockDecompressor.read(destination, offset, length);
    }

    if (bytesRead == -1) {
      if (initialiseNextBlock()) {
        bytesRead = this.blockDecompressor.read(destination, offset, length);
      }
    }

    return bytesRead;
  }
}
