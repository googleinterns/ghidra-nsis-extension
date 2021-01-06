package nsis.tests;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import nsis.NsisAnalyzer;
import nsis.format.InvalidFormatException;

public class NsisAnalyzerTest {
  @Test
  public void testNsisCreationLZMACompressed() throws IOException, InvalidFormatException {
    for(int i = 1; i <= 0x46; i++) {
      assertTrue(NsisAnalyzer.operations.containsKey(i));
    }
  }
}
