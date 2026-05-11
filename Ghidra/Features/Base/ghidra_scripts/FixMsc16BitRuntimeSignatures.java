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
//@category Analysis
//@description Fix MSC 5.x 16-bit runtime function signatures (__aNlmul, __aNldiv, __aNlrem)
//@menupath Analysis.Fix MSC 16-bit Runtime Signatures

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class FixMsc16BitRuntimeSignatures extends GhidraScript {

	private static final Set<String> TARGET_NAMES = Set.of(
		"__aNlmul", "__aNldiv", "__aNlrem",
		"_aNlmul", "_aNldiv", "_aNlrem"
	);

	private static final String CALLING_CONVENTION = "__cdecl16near";

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			println("No program is open.");
			return;
		}

		FunctionManager funcManager = currentProgram.getFunctionManager();
		int fixedCount = 0;

		FunctionIterator functions = funcManager.getFunctions(true);
		while (functions.hasNext() && !monitor.isCancelled()) {
			Function func = functions.next();
			String name = func.getName();

			if (!TARGET_NAMES.contains(name)) {
				continue;
			}

			println("Found function: " + name + " at " + func.getEntryPoint());

			try {
				LongDataType longType = new LongDataType();

				// Set return type
				func.setReturnType(longType, SourceType.USER_DEFINED);

				// Set calling convention
				try {
					func.setCallingConvention(CALLING_CONVENTION);
					println("  Set calling convention to " + CALLING_CONVENTION);
				}
				catch (Exception e) {
					println("  Calling convention " + CALLING_CONVENTION +
						" not available, keeping default: " + e.getMessage());
				}

				// Set parameters: long a, long b
				Parameter paramA = new ParameterImpl("a", longType, currentProgram);
				Parameter paramB = new ParameterImpl("b", longType, currentProgram);

				func.replaceParameters(List.of(paramA, paramB),
					Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false,
					SourceType.USER_DEFINED);

				println("  Applied signature: long " + name + "(long a, long b)");
				fixedCount++;
			}
			catch (Exception e) {
				println("  ERROR updating " + name + ": " + e.getMessage());
			}
		}

		println("Done. Fixed " + fixedCount + " function(s).");
	}
}
