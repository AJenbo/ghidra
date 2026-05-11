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
//@description Fix MSC 5.x/6.x 16-bit runtime function signatures for better decompilation
//@menupath Analysis.Fix MSC 16-bit Runtime Signatures

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Fixes function signatures for Microsoft C 5.x/6.x 16-bit runtime library functions.
 *
 * These compilers generate calls to helper functions for 32-bit arithmetic that the
 * decompiler cannot automatically type correctly. Without correct signatures, the
 * decompiler shows ugly patterns like:
 *   __aNlmul(val, (int)val >> 0xf, uVar1, (int)uVar1 >> 0xf)
 * instead of the correct:
 *   __aNlmul((long)val, (long)uVar1)
 *
 * Supported functions:
 *   __aNlmul  - long multiply:      long __aNlmul(long a, long b)
 *   __aNldiv  - long divide:         long __aNldiv(long a, long b)
 *   __aNlrem  - long remainder:      long __aNlrem(long a, long b)
 *   __aNNaldiv - long divide in-place: void __aNNaldiv(long *a, long b)
 *   __aNNalmul - long multiply in-place: void __aNNalmul(long *a, long b)
 *   __aNNalrem - long remainder in-place: void __aNNalrem(long *a, long b)
 *   __aFlmul  - long multiply (far): long __aFlmul(long a, long b)
 *   __aFldiv  - long divide (far):   long __aFldiv(long a, long b)
 *   __aFlrem  - long remainder (far): long __aFlrem(long a, long b)
 *   __aFNalshl - long shift left:    long __aFNalshl(long val, int count)
 *   __aFNalshr - long shift right (unsigned): unsigned long __aFNalshr(unsigned long val, int count)
 *   __aFNalsar - long shift right (signed): long __aFNalsar(long val, int count)
 *
 * All names are checked with both single and double underscore prefixes.
 */
public class FixMsc16BitRuntimeSignatures extends GhidraScript {

	private static final String CC_CDECL = "__cdecl16near";

	/** Signature types for MSC runtime functions */
	private enum SigType {
		/** long func(long a, long b) */
		LONG_LONG_LONG,
		/** void func(long *a, long b) - in-place operation */
		VOID_LONGPTR_LONG,
		/** long func(long val, int count) - shift operation */
		LONG_LONG_INT,
		/** unsigned long func(unsigned long val, int count) - unsigned shift */
		ULONG_ULONG_INT
	}

	/** Map of function base names (without prefix) to their signature type */
	private static final Map<String, SigType> FUNC_SIGS = new LinkedHashMap<>();
	static {
		// Near model: __aN* prefix
		FUNC_SIGS.put("aNlmul", SigType.LONG_LONG_LONG);
		FUNC_SIGS.put("aNldiv", SigType.LONG_LONG_LONG);
		FUNC_SIGS.put("aNlrem", SigType.LONG_LONG_LONG);
		FUNC_SIGS.put("aNNaldiv", SigType.VOID_LONGPTR_LONG);
		FUNC_SIGS.put("aNNalmul", SigType.VOID_LONGPTR_LONG);
		FUNC_SIGS.put("aNNalrem", SigType.VOID_LONGPTR_LONG);
		// Far model: __aF* prefix
		FUNC_SIGS.put("aFlmul", SigType.LONG_LONG_LONG);
		FUNC_SIGS.put("aFldiv", SigType.LONG_LONG_LONG);
		FUNC_SIGS.put("aFlrem", SigType.LONG_LONG_LONG);
		// Shift helpers
		FUNC_SIGS.put("aFNalshl", SigType.LONG_LONG_INT);
		FUNC_SIGS.put("aFNalshr", SigType.ULONG_ULONG_INT);
		FUNC_SIGS.put("aFNalsar", SigType.LONG_LONG_INT);
	}

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			println("No program is open.");
			return;
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataType longType = new LongDataType(dtm);
		DataType ulongType = new UnsignedLongDataType(dtm);
		DataType intType = new IntegerDataType(dtm);
		DataType voidType = new VoidDataType(dtm);
		DataType longPtrType = new PointerDataType(longType, currentProgram.getDefaultPointerSize());

		FunctionManager funcManager = currentProgram.getFunctionManager();
		int fixedCount = 0;

		FunctionIterator functions = funcManager.getFunctions(true);
		while (functions.hasNext() && !monitor.isCancelled()) {
			Function func = functions.next();
			String name = func.getName();

			// Try to match: strip leading underscores and look up
			SigType sigType = lookupSignature(name);
			if (sigType == null) {
				continue;
			}

			println("Found: " + name + " at " + func.getEntryPoint() + " -> " + sigType);

			try {
				// Set calling convention
				try {
					func.setCallingConvention(CC_CDECL);
				}
				catch (Exception e) {
					println("  Warning: could not set calling convention: " + e.getMessage());
				}

				List<Parameter> params = new ArrayList<>();
				DataType retType;

				switch (sigType) {
					case LONG_LONG_LONG:
						retType = longType;
						params.add(new ParameterImpl("a", longType, currentProgram));
						params.add(new ParameterImpl("b", longType, currentProgram));
						break;
					case VOID_LONGPTR_LONG:
						retType = voidType;
						params.add(new ParameterImpl("a", longPtrType, currentProgram));
						params.add(new ParameterImpl("b", longType, currentProgram));
						break;
					case LONG_LONG_INT:
						retType = longType;
						params.add(new ParameterImpl("val", longType, currentProgram));
						params.add(new ParameterImpl("count", intType, currentProgram));
						break;
					case ULONG_ULONG_INT:
						retType = ulongType;
						params.add(new ParameterImpl("val", ulongType, currentProgram));
						params.add(new ParameterImpl("count", intType, currentProgram));
						break;
					default:
						continue;
				}

				func.setReturnType(retType, SourceType.USER_DEFINED);
				func.replaceParameters(params,
					Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false,
					SourceType.USER_DEFINED);

				println("  Applied: " + formatSignature(name, retType, params));
				fixedCount++;
			}
			catch (Exception e) {
				println("  ERROR: " + e.getMessage());
			}
		}

		println("\nDone. Fixed " + fixedCount + " function(s).");
	}

	/**
	 * Look up the signature type for a function name.
	 * Handles both single underscore (_aNlmul) and double underscore (__aNlmul) prefixes.
	 */
	private SigType lookupSignature(String name) {
		// Strip one or two leading underscores
		String baseName = name;
		if (baseName.startsWith("__")) {
			baseName = baseName.substring(2);
		}
		else if (baseName.startsWith("_")) {
			baseName = baseName.substring(1);
		}
		else {
			return null;
		}
		return FUNC_SIGS.get(baseName);
	}

	private String formatSignature(String name, DataType retType, List<Parameter> params) {
		StringBuilder sb = new StringBuilder();
		sb.append(retType.getDisplayName()).append(" ").append(name).append("(");
		for (int i = 0; i < params.size(); i++) {
			if (i > 0) sb.append(", ");
			sb.append(params.get(i).getDataType().getDisplayName());
			sb.append(" ").append(params.get(i).getName());
		}
		sb.append(")");
		return sb.toString();
	}
}
