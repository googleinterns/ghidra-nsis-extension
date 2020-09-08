package nsis.compression.bzip2;

import java.io.IOException;

public class BZip2NsisBlockDecompressor extends BZip2BlockDecompressor {

  public BZip2NsisBlockDecompressor(BZip2BitInputStream bitInputStream, int blockSize)
      throws IOException {
    this.bitInputStream = bitInputStream;
    this.bwtBlock = new byte[blockSize];

    final int bwtStartPointer;
    bwtStartPointer = this.bitInputStream.readBits (24);

    // Read block data and decode through to the Inverse Burrows Wheeler Transform stage
    BZip2HuffmanStageDecoder huffmanDecoder = readHuffmanTables();
    decodeHuffmanData (huffmanDecoder);
    initialiseInverseBWT (bwtStartPointer);
  }

}
