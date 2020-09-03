package nsis.format;

public class InvalidFormatException extends Exception {

  private static final long serialVersionUID = 1L;
  private String message;

  public InvalidFormatException(String details) {
    this.message = details;
  }

  public String toString() {
    return message;
  }

}
