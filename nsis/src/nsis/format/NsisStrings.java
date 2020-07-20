package nsis.format;

import ghidra.app.util.bin.BinaryReader;

public class NsisStrings {
	private int sectionLength;

	/**
	 * When creating a NsisStrings object, the pointer of the reader is advanced to
	 * the end of the strings section.
	 * 
	 * @param reader
	 * @param stringsSectionOffset
	 * @param languageSectionOffset
	 */
	public NsisStrings(BinaryReader reader, int stringsSectionOffset, int languageSectionOffset) {
		this.sectionLength = languageSectionOffset - stringsSectionOffset;
		reader.setPointerIndex(reader.getPointerIndex() + this.sectionLength);
	}

	public int getStringsSectionLength() {
		return this.sectionLength;
	}
}
