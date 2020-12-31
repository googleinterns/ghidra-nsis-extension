/*
 * ### IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package nsis;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import nsis.file.NsisConstants;
import nsis.file.NsisLangTableMapper;
import nsis.instructions.Call;
import nsis.instructions.CopyFiles;
import nsis.instructions.CreateDir;
import nsis.instructions.DeleteFile;
import nsis.instructions.DeleteReg;
import nsis.instructions.Execute;
import nsis.instructions.GetDlgItem;
import nsis.instructions.IfFileExists;
import nsis.instructions.IntCmp;
import nsis.instructions.IntFmt;
import nsis.instructions.IntOp;
import nsis.instructions.Jmp;
import nsis.instructions.MessageBox;
import nsis.instructions.Operation;
import nsis.instructions.PushPop;
import nsis.instructions.ReadRegStr;
import nsis.instructions.RegisterDLL;
import nsis.instructions.Return;
import nsis.instructions.RmDir;
import nsis.instructions.SendMessage;
import nsis.instructions.SetFlag;
import nsis.instructions.StrCpy;
import nsis.instructions.StrLen;
import nsis.instructions.StrCmp;
import nsis.instructions.UpdateText;
import nsis.instructions.WriteRegValue;

/**
 * This analyzer finds NSIS bytecode and will try to decompile it into the
 * original NSIS script.
 */
public class NsisAnalyzer extends AbstractAnalyzer {

  private NsisLangTableMapper langTableMapper = new NsisLangTableMapper();
  private MemoryBlock stringsBlock;
  private MemoryBlock entriesBlock;
  private ReferenceManager referenceManager;
  private Listing listing;
  private Map<Integer, String> generatedStings = new HashMap<Integer, String>();
  private EquateTable equateTable;
  private MessageLog log;
  private int charWidth = 1;

  public NsisAnalyzer() {
    super("NSIS script decompiler", "Decompiles NSIS bytecode into NSIS script.",
        AnalyzerType.BYTE_ANALYZER);
  }

  /**
   * Determines if the analyzer should be enabled by default
   */
  @Override
  public boolean getDefaultEnablement(Program program) {
    return true;
  }

  /**
   * Determines if this analyzer can analyze the given program.
   */
  @Override
  public boolean canAnalyze(Program program) {
    String format = program.getExecutableFormat();
    if (format.equals(NsisLoader.NE_NAME)) {
      return true;
    }
    return false;
  }

  /**
   * Registers the options provided to the user for this analyzer.
   */
  @Override
  public void registerOptions(Options options, Program program) {
  }

  /**
   * Perform analysis when things get added to the 'program'. Return true if the
   * analysis succeeded.
   */
  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {

    this.stringsBlock = program.getMemory().getBlock(NsisConstants.STRINGS_MEMORY_BLOCK_NAME);
    this.entriesBlock = program.getMemory().getBlock(NsisConstants.ENTRIES_MEMORY_BLOCK_NAME);
    this.referenceManager = program.getReferenceManager();
    this.listing = program.getListing();
    this.equateTable = program.getEquateTable();
    this.log = log;

    try {
      this.updateCharWidth();
    } catch (MemoryAccessException e1) {
      // If there is no strings block we might as well quit
      return false;
    }

    Data langTables = program.getListing().getDefinedDataAt(
        program.getMemory().getBlock(NsisConstants.LANGTABLES_MEMORY_BLOCK_NAME).getStart());
    this.analyzeLangTable(langTables);

    AddressSet modifiedAddrSet = disassembleByteCode(program, this.entriesBlock, monitor);

    if (!modifiedAddrSet.isEmpty()) {
      InstructionIterator instructions = program.getListing().getInstructions(modifiedAddrSet,
          /* forward direction */ true);

      for (Instruction instr : instructions) {
        try {
          Operation op = toOperation(instr);
          if (op != null) {
            op.fixUp(instr, this);
          }
        } catch (MemoryAccessException e) {
          monitor.setMessage("Unable to revolve parameters at instruction: " + instr
              .getAddressString(/* display mnemonic */ true, /* pad address if necessary */ true));
        }
      }
    }

    return true;
  }

  /**
   * Determines if the file was compiled with unicode support. Checks the first
   * two bytes of the Stings block. The first two bytes should be null for
   * Unicode, otherwise ASCII.
   * 
   * @throws MemoryAccessException
   */
  private void updateCharWidth() throws MemoryAccessException {
    byte[] b = new byte[2];
    this.stringsBlock.getBytes(this.stringsBlock.getStart(), b);

    if (b[0] == 0 && b[1] == 0) {
      this.charWidth = 2;
    }
  }

  /**
   * The language table is how NSIS file support multiple languages. There is a
   * table for each supported language. The table contains pointers to each
   * language string. In theory each table has the same number of entries and each
   * entry points to string in the relevant language that means the same thing in
   * each language. This function parses all the language table and makes data
   * references between the language table and the strings memory section.
   * 
   * @param langTables the language table data.
   */
  private void analyzeLangTable(Data langTables) {

    for (int i = 0; i < langTables.getNumComponents(); i++) {
      Data langTable = langTables.getComponent(i);
      int langID;
      try {
        langID = langTable.getComponent(0).getComponent(0).getInt(0);
      } catch (MemoryAccessException e) {
        e.printStackTrace();
        break;
      }
      for (int j = 1; j < langTable.getNumComponents(); j++) {
        Data entry = langTable.getComponent(j);
        int stringOffset;
        try {
          stringOffset = entry.getInt(0) * this.charWidth;

          if (stringOffset == 0)
            continue;
          this.langTableMapper.addStringOffset(langID, j - 1, stringOffset);
          Address stringAddr = stringsBlock.getStart().add(stringOffset);
          if (!this.getListing().isUndefined(stringAddr, stringAddr)) {
            try {
              DataType dataType = TerminatedUnicodeDataType.dataType;
              if (this.charWidth == 1) {
                dataType = TerminatedStringDataType.dataType;
              }
              this.getListing().createData(stringAddr, dataType);
            } catch (CodeUnitInsertionException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            } catch (DataTypeConflictException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            }
          }
          entry.addValueReference(stringAddr, RefType.DATA_IND);
        } catch (MemoryAccessException e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }
      }
    }
  }

  /**
   * Returns the Operation object associated with the given instruction. The
   * association is made with the opcode of the instruction.
   * 
   * @param instruction to create the Operation object with
   * @return the Operation object associated to the instruction
   * @throws MemoryAccessException
   */
  private Operation toOperation(Instruction instr) throws MemoryAccessException {
    switch (instr.getInt(0)) {
    case Return.OPCODE: // 0x1
      return new Return();
    case Jmp.OPCODE: // 0x2
      return new Jmp();
    case Call.OPCODE: // 0x5
      return new Call();
    case UpdateText.OPCODE: // 0x6
      return new UpdateText();
    case CreateDir.OPCODE: // 0xb
      return new CreateDir();
    case IfFileExists.OPCODE: // 0xc
      return new IfFileExists();
    case SetFlag.OPCODE: // 0xd
      return new SetFlag();
    case DeleteFile.OPCODE: // 0x15
      return new DeleteFile();
    case MessageBox.OPCODE: // 0x16
      return new MessageBox();
    case RmDir.OPCODE: // 0x17
      return new RmDir();
    case StrLen.OPCODE: // 0x18
      return new StrLen();
    case StrCpy.OPCODE: // 0x19
      return new StrCpy();
    case StrCmp.OPCODE: // 0x1a
      return new StrCmp();
    case IntCmp.OPCODE: // 0x1c
      return new IntCmp();
    case IntOp.OPCODE: // 0x1d
      return new IntOp();
    case IntFmt.OPCODE: // 0x1e
      return new IntFmt();
    case PushPop.OPCODE: // 0x1f
      return new PushPop();
    case SendMessage.OPCODE: // 0x21
      return new SendMessage();
    case GetDlgItem.OPCODE: // 0x23
      return new GetDlgItem();
    case Execute.OPCODE: // 0x29
      return new Execute();
    case RegisterDLL.OPCODE: // 0x2c
      return new RegisterDLL();
    case CopyFiles.OPCODE: // 0x2e
      return new CopyFiles();
    case DeleteReg.OPCODE: // 0x32
      return new DeleteReg();
    case WriteRegValue.OPCODE: // 0x33
      return new WriteRegValue();
    case ReadRegStr.OPCODE: // 0x34
      return new ReadRegStr();

    default:
      return null;
    }
  }

  /**
   * Disassembles the byte code in the specified memory block.
   * 
   * @param program     to instantiate the disassembler with
   * @param memoryBlock to perform the disassembly on
   * @param monitor     the TaskMonitor object to monitor the operation
   * @return the AddressSet of the disassembled instructions
   */
  private AddressSet disassembleByteCode(Program program, MemoryBlock memoryBlock,
      TaskMonitor monitor) {
    Disassembler disassembler = Disassembler.getDisassembler(program, monitor,
        /* Object to notify */ null);
    AddressSet entriesAddrSet = new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd());
    return disassembler.disassemble(entriesAddrSet.getMinAddress(), entriesAddrSet,
        /* follow flow */ true);
  }

  /**
   * @param langID identifies which language table to use
   * @param idx    the index of the entry to choose
   * @return this integer offset into the string data section where the language
   *         string can be found.
   */
  public Integer getStringFromLang(int langID, int idx) {
    return this.langTableMapper.getStringOffset(langID, idx);
  }

  public Integer getStringFromLang(int idx) {
    return this.langTableMapper.getStringOffset(idx);
  }

  /**
   * This function implements a macro from the NSIS code for decoding a byte value
   * stored in a short.
   * 
   * @param addr address where to decode
   * @return the decoded value
   * @throws MemoryAccessException
   * @throws AddressOutOfBoundsException
   */
  private int decodeShort(Address addr) throws MemoryAccessException, AddressOutOfBoundsException {
    // #define DECODE_SHORT(c) (((((char*)c)[1] & 0x7F) << 7) | (((char*)c)[0] &
    // 0x7F))
    int param1 = this.stringsBlock.getByte(addr);
    int param2 = this.stringsBlock.getByte(addr.add(1));
    return ((param2 & 0x7f) << 7) | (param1 & 0x7f);
  }

  public String buildString(int offset) throws MemoryAccessException {
    return buildString(offset, true);
  }

  /**
   * Builds a string based on the offset into the strings table. NSIS byte code
   * arguments can refer to the string table. The string table contains strings as
   * well as encoded references to variables ($1, $2, $R1, $R2), built-ins
   * ($EXEDIR, $EXEPATH, etc.), Windows shell environment variables ($APPDATA,
   * etc.), and/or the language table.
   * 
   * This function goes to the string table at the specified offset and resolves
   * the reference into a printable string.
   * 
   * @param offset       the offset into the string table to decode
   * @param adjustOffset if the offset needs to be adjusted by the character
   *                     width. For unicode sometimes the offset needs to be
   *                     multipled by 2 to find the correct string.
   * @return the built string
   * @throws MemoryAccessException
   */
  public String buildString(int offset, boolean adjustOffset) throws MemoryAccessException {
    if (this.generatedStings.containsKey(offset)) {
      return this.generatedStings.get(offset);
    }

    StringBuffer str = new StringBuffer();
    if (offset < 0) {
      // Handle language
      return this.buildString(this.langTableMapper.getStringOffset(-(offset + 1)), false);
    } else {
      int i = 0;

      int adjustedOffset = offset;
      if (adjustOffset) {
        adjustedOffset *= this.charWidth;
      }

      Charset charset = Charset.forName("US-ASCII");
      byte[] tmpChar = new byte[this.charWidth];
      if (this.charWidth == 2) {
        charset = Charset.forName("UTF-16LE");
      }

      while (i < NsisConstants.NSIS_MAX_STRLEN) {
        Address curAddr = this.stringsBlock.getStart().add(adjustedOffset + i);
        byte c = this.stringsBlock.getByte(curAddr);

        if (c == 0) {
          break;
        }

        if (java.lang.Math.abs(c) == NsisConstants.NS_LANG_CODE) {
          int langIdx = this.decodeShort(curAddr.add(this.charWidth));
          str.append(buildString(this.langTableMapper.getStringOffset(langIdx), false));
          i += this.charWidth + StructConverter.WORD.getLength();
        } else if (java.lang.Math.abs(c) == NsisConstants.NS_SHELL_CODE) {
          int curUserParam = this.stringsBlock.getByte(curAddr.add(this.charWidth));
          int allUserParam = this.stringsBlock.getByte(curAddr.add(this.charWidth + 1));
          if (NsisConstants.USER_SHELL.containsKey(curUserParam)) {
            str.append(NsisConstants.USER_SHELL.get(curUserParam));
          } else if (NsisConstants.USER_SHELL.containsKey(allUserParam)) {
            str.append(NsisConstants.USER_SHELL.get(allUserParam));
          }
          i += this.charWidth + StructConverter.WORD.getLength();
        } else if (java.lang.Math.abs(c) == NsisConstants.NS_VAR_CODE) {
          int param = this.decodeShort(curAddr.add(this.charWidth));
          str.append(this.getVarString(param));
          i += this.charWidth + StructConverter.WORD.getLength();
        } else if (java.lang.Math.abs(c) == NsisConstants.NS_SKIP_CODE) {
          this.stringsBlock.getBytes(curAddr.add(this.charWidth), tmpChar);
          str.append(new String(tmpChar, charset));
          i += this.charWidth * 2;
        } else if (NsisConstants.CHAR_ESCAPES.containsKey(java.lang.Math.abs(c))) {
          str.append(NsisConstants.CHAR_ESCAPES.get(java.lang.Math.abs(c)));
          i += this.charWidth;
        } else {
          this.stringsBlock.getBytes(curAddr, tmpChar);
          str.append(new String(tmpChar, charset));
          i += this.charWidth;
        }
      }
    }

    String retVal = str.toString();

    if (retVal.length() == 0) {
      return null;
    }

    if (!this.generatedStings.containsKey(offset)) {
      this.generatedStings.put(offset, retVal);
    }

    return retVal;
  }

  /**
   * Resolves a direct variable reference. Some instruction arguments can only be
   * a variable in this case the variable encoding is not looked up in the string
   * table but instead is specified directly. An equate is created between the
   * arugment and the variable string.
   * 
   * @param instr the instruction containing the argument to equate
   * @param arg   the argument to equate
   * @return the generated variable string
   * @throws MemoryAccessException
   */
  public String resolveVariable(Instruction instr, NsisConstants.ARGS arg)
      throws MemoryAccessException {
    int argVal = instr.getInt(arg.offset);

    String val = this.getVarString(argVal);

    if (val == null) {
      return null;
    }

    this.safeEquate(instr, arg, val, argVal);

    return val;
  }

  /**
   * Creates a display string for a variable. The display string is constructed
   * based on the varId.
   * 
   * @param varId the variable ID
   * @return the created string
   */
  private String getVarString(int varId) {
    if (NsisConstants.USER_VAR_NAMES.containsKey(varId)) {
      return NsisConstants.USER_VAR_NAMES.get(varId);
    } else if (varId < 10) {
      return String.format("$%d", varId);
    } else if (varId < 20) {
      return String.format("$R%d", varId - 10);
    } else {
      return String.format("$VAR_%d", varId - NsisConstants.USER_VARIABLE_BEGIN);
    }
  }

  /**
   * Resolves a string from the specified instruction and agument. Create an
   * equate linking in the argument to the created string.
   * 
   * @param instr this instruction to update
   * @param arg   the specific argument to update
   * @return the generated string, an equate is also created for this.
   * @throws MemoryAccessException
   */
  public String resolveString(Instruction instr, NsisConstants.ARGS arg)
      throws MemoryAccessException {
    int argVal = instr.getInt(arg.offset);

    String val = buildString(argVal);

    if (val == null) {
      return null;
    }

    this.safeEquate(instr, arg, val, argVal);

    return val;
  }

  /**
   * Attempts to safely create an equate from the specified instruction and
   * argument to the specified name. Ghidra requires all equate names to be
   * unique. Unfortunately, NSIS byte code can refer to a variable directly by
   * index (0x0 refers to variable $1) or by an offset into the string table where
   * the reference to the variable will be encoded.
   * 
   * If this function finds a conflict it attempts to append '_' characters until
   * a unique name is found.
   * 
   * @param instr the instruction to create the equate for
   * @param arg   the argument to create the equate for
   * @param name  the name to replace the value with
   * @param value the value, this should equal the value of the argument
   */
  public void safeEquate(Instruction instr, NsisConstants.ARGS arg, String name, long value) {
    if (name.trim().length() == 0) {
      byte[] bytes = name.getBytes(Charset.forName("UTF-8"));
      StringBuffer buf = new StringBuffer();
      for (int i = 0; i < bytes.length; i++) {
        buf.append(String.format("\\x%x", bytes[i]));
      }
      name = buf.toString();
    }

    Equate eq = this.equateTable.getEquate(name);
    if (eq != null) {
      while (eq != null && eq.getValue() != value) {
        name += "_";
        eq = this.equateTable.getEquate(name);
      }
    }

    if (eq == null) {
      try {
        try {
          eq = this.equateTable.createEquate(name, value);
        } catch (DuplicateNameException e) {
          this.log.appendException(e);
          this.log.appendMsg(String.format("%s", instr.getMnemonicString()));
          // This would be very weird since we just checked if it existed
          e.printStackTrace();
        }
      } catch (InvalidInputException e) {
        this.log.appendException(e);
        this.log.appendMsg(String.format("%s", instr.getMnemonicString()));
        e.printStackTrace();
      }
    }

    eq.addReference(instr.getAddress(), arg.index);
  }

  /**
   * Maps Windows registry hive constants to printable strings and associates the
   * argument and in the instruction with the generated string. Also creates an
   * equate between the argument and the generated string.
   * 
   * @param instr the instruction to update
   * @param arg   the argument of the instruction that contains the registry hive
   *              constant
   * @return the generated string or null if it could not be created
   * @throws MemoryAccessException
   */
  public String resolveRegistryHive(Instruction instr, NsisConstants.ARGS arg)
      throws MemoryAccessException {
    int argVal = instr.getInt(arg.offset);
    String val;

    if (NsisConstants.REG_HIVES.containsKey(argVal)) {
      val = NsisConstants.REG_HIVES.get(argVal);
    } else {
      return null;
    }

    this.safeEquate(instr, arg, val, argVal);

    return val;
  }

  /**
   * Get the address in memory associated to the position 'instruction number' in
   * the entries block
   * 
   * @param instructionNumber, the instruction number for which the address is
   *                           needed
   * @return the address associated to that instruction
   */
  public Address getInstructionAddress(int instructionNumber) {
    long instructionOffset = (instructionNumber - 1) * NsisConstants.INSTRUCTION_BYTE_LENGTH;
    return this.entriesBlock.getStart().add(instructionOffset);
  }

  /**
   * Creates a condition jump reference between the argument in the specified
   * instruction and the location where that argument points to.
   * 
   * @param instr the instruction to update
   * @param arg   the argument that contains the jump location
   * @return the number of instruction that is jumped to
   * @throws MemoryAccessException
   */
  public int resolveConditionalJump(Instruction instr, NsisConstants.ARGS arg)
      throws MemoryAccessException {
    int instrNumber = instr.getInt(arg.offset);

    if (instrNumber != 0) {
      this.referenceManager.addMemoryReference(instr.getAddress(),
          this.getInstructionAddress(instrNumber), RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS,
          arg.index);
    }
    return instrNumber;
  }

  /**
   * Creates an unconditional jump reference between the argument in the specified
   * instruction and the location where that argument points to.
   * 
   * @param instr the instruction to update
   * @param arg   the argument that contains the jump location
   * @return the number of instruction that is jumped to
   * @throws MemoryAccessException
   */
  public int resolveUnconditionalJump(Instruction instr, NsisConstants.ARGS arg)
      throws MemoryAccessException {
    int instrNumber = instr.getInt(arg.offset);

    referenceManager.addMemoryReference(instr.getAddress(), this.getInstructionAddress(instrNumber),
        RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, arg.index);

    return instrNumber;
  }

  public Listing getListing() {
    return this.listing;
  }
}
