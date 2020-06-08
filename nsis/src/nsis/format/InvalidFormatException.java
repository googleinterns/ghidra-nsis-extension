package nsis.format;

public class InvalidFormatException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String details;
	
	public InvalidFormatException(String details) {
		this.details = details;
	}
	
	public String toString() {
		return details;
	}

}
