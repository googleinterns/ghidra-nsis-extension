/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nsis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer finds NSIS bytecode and will try to decompile it into the
 * original NSIS script.
 */
public class NsisAnalyzer extends AbstractAnalyzer {

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

		// TODO: Perform analysis when things get added to the 'program'. Return
		// true if
		// the
		// analysis succeeded.

		return false;
	}
}
