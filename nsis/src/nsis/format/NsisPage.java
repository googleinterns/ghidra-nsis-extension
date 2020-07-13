package nsis.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class NsisPage implements StructConverter {

	private static final int NB_PARAMETERS = 5;
	private int dlg_id;
	private int wndproc_id;
	private int prefunc;
	private int showfunc;
	private int leavefunc;
	private int flags;
	private int caption;
	private int back;
	private int next;
	private int clicknext;
	private int cancel;
	private int[] parms = new int[NB_PARAMETERS];

	private final static Structure STRUCTURE;

	static {
		// Values are named after the NSIS implementation of page struct:
		// https://sourceforge.net/p/nsis/code/HEAD/tree/NSIS/trunk/Source/exehead/fileform.h#l448
		STRUCTURE = new StructureDataType("Page", 0);
		STRUCTURE.add(DWORD, DWORD.getLength(), "dlg_id", "dialog resource id");
		STRUCTURE.add(DWORD, DWORD.getLength(), "wndproc_id", "");
		STRUCTURE.add(DWORD, DWORD.getLength(), "prefunc",
				"called before the page is created, or if custom to show the page");
		STRUCTURE.add(DWORD, DWORD.getLength(), "showfunc", "called right before page is shown");
		STRUCTURE.add(DWORD, DWORD.getLength(), "leavefunc",
				"called when the user leaves to the next page");
		STRUCTURE.add(DWORD, DWORD.getLength(), "flags", "page flags");
		STRUCTURE.add(DWORD, DWORD.getLength(), "caption", "");
		STRUCTURE.add(DWORD, DWORD.getLength(), "back", "");
		STRUCTURE.add(DWORD, DWORD.getLength(), "next", "");
		STRUCTURE.add(DWORD, DWORD.getLength(), "clicknext", "");
		STRUCTURE.add(DWORD, DWORD.getLength(), "cancel", "");
		STRUCTURE.add(new ArrayDataType(DWORD, NB_PARAMETERS, DWORD.getLength()), 0, "parms",
				"raw parameters");
	}

	public NsisPage(BinaryReader reader) throws IOException {
		this.dlg_id = reader.readNextInt();
		this.wndproc_id = reader.readNextInt();
		this.prefunc = reader.readNextInt();
		this.showfunc = reader.readNextInt();
		this.leavefunc = reader.readNextInt();
		this.flags = reader.readNextInt();
		this.caption = reader.readNextInt();
		this.back = reader.readNextInt();
		this.clicknext = reader.readNextInt();
		this.cancel = reader.readNextInt();
		this.parms = reader.readNextIntArray(NB_PARAMETERS);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return STRUCTURE;
	}

}
