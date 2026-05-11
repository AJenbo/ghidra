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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
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
		/** long func(long a, long b) — stack-based */
		LONG_LONG_LONG,
		/** void func(long *a, long b) — in-place operation, stack-based */
		VOID_LONGPTR_LONG,
		/** long func(long val, int count) — stack-based shift (if exists) */
		LONG_LONG_INT,
		/** unsigned long func(unsigned long val, int count) — stack-based shift (if exists) */
		ULONG_ULONG_INT,
		/** Shift helper — register-based, just fix return type to long */
		RETURN_LONG_ONLY,
		/** Shift helper — register-based, just fix return type to unsigned long */
		RETURN_ULONG_ONLY
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
		// Shift helpers — register-based calling convention, just fix return type
		FUNC_SIGS.put("aFNalshl", SigType.RETURN_LONG_ONLY);
		FUNC_SIGS.put("aFNalshr", SigType.RETURN_ULONG_ONLY);
		FUNC_SIGS.put("aFNalsar", SigType.RETURN_LONG_ONLY);
	}

	/**
	 * Byte-pattern signatures for MSC 5.x/6.x runtime functions.
	 * Each entry maps a byte-pattern prefix at a function entry to a function name.
	 *
	 * NOTE: These patterns must be validated against actual binaries.
	 * The byte sequences are derived from MSC 5.x SLIBCE.LIB / SLIBC7.LIB.
	 * Patterns use mask bytes: 0xFF = must match, 0x00 = wildcard.
	 *
	 * To add patterns for a specific binary, disassemble the runtime functions
	 * and capture their first N bytes as patterns here.
	 */
	private static class BytePattern {
		String name;      // base name without underscores (e.g. "aNlmul")
		byte[] bytes;     // byte pattern to match
		byte[] mask;      // mask (0xff = must match, 0x00 = wildcard)

		BytePattern(String name, byte[] bytes, byte[] mask) {
			this.name = name;
			this.bytes = bytes;
			this.mask = mask;
		}

		BytePattern(String name, byte[] bytes) {
			this.name = name;
			this.bytes = bytes;
			this.mask = new byte[bytes.length];
			Arrays.fill(this.mask, (byte) 0xff);
		}
	}

	/**
	 * Known byte patterns for MSC 5.x runtime functions.
	 * These are empty by default — add patterns from your specific binary.
	 * Use the Ghidra listing or hex dump to capture entry bytes.
	 *
	 * Example for a specific binary's __aNlmul:
	 *   new BytePattern("aNlmul", new byte[]{0x55, (byte)0x8b, (byte)0xec, ...})
	 */
	private static final BytePattern[] BYTE_PATTERNS = {
		// Add patterns here as they are identified from specific binaries.
		// See script description for format.
	};

	/**
	 * Heuristic: identify likely long-shift runtime functions by their
	 * structural properties. Shift helpers (__aFNalshl, __aFNalshr, __aFNalsar)
	 * use a register-based calling convention (value in DX:AX, count in CL).
	 * Ghidra's auto-analysis typically detects 0 stack parameters since the
	 * values are passed in registers. These are small functions (typically
	 * 15-50 bytes) called from multiple sites.
	 *
	 * Classification:
	 * - All three are similar size. We distinguish by instruction patterns:
	 *   - __aFNalshl: contains SHL + RCL (shift left with carry propagation)
	 *   - __aFNalshr: contains SHR + RCR (unsigned shift right with carry)
	 *   - __aFNalsar: contains SAR + RCR (signed/arithmetic shift right with carry)
	 * - If instruction analysis fails, we fall back to address ordering
	 *   (MSC links shl, then shr, then sar).
	 */
	private Map<Function, String> identifyShiftHelpers(FunctionManager funcManager) {
		Map<Function, String> identified = new LinkedHashMap<>();

		FunctionIterator iter = funcManager.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function func = iter.next();
			if (!func.getName().startsWith("FUN_")) continue;

			// Shift helpers use register-based calling convention:
			// value in DX:AX, count in CL. Ghidra's auto-analysis typically
			// detects 0 stack parameters (registers aren't seen as params).
			// Accept 0-3 detected params to be safe.
			Parameter[] params = func.getParameters();
			if (params.length > 3) continue;

			// Must be small (shift helpers are ~15-50 bytes)
			long bodySize = func.getBody().getNumAddresses();
			if (bodySize > 60) continue;

			// Must be called from at least 2 sites
			int callCount = 0;
			var refs = currentProgram.getReferenceManager()
				.getReferencesTo(func.getEntryPoint());
			while (refs.hasNext()) {
				refs.next();
				callCount++;
			}
			if (callCount < 2) continue;

			// The defining feature: must contain shift+rotate instruction pairs
			String name = classifyShiftByInstructions(func);
			if (name != null) {
				identified.put(func, name);
			}
		}

		return identified;
	}

	/**
	 * Classify a shift helper by scanning its instructions for SHL/SHR/SAR + RCL/RCR.
	 * Returns the base name (e.g. "aFNalshl") or null if unrecognized.
	 */
	private String classifyShiftByInstructions(Function func) {
		boolean hasSHL = false, hasSHR = false, hasSAR = false;
		boolean hasRCL = false, hasRCR = false;

		InstructionIterator instrIter = currentProgram.getListing()
			.getInstructions(func.getBody(), true);
		while (instrIter.hasNext()) {
			Instruction instr = instrIter.next();
			String mnemonic = instr.getMnemonicString().toUpperCase();
			switch (mnemonic) {
				case "SHL": hasSHL = true; break;
				case "SHR": hasSHR = true; break;
				case "SAR": hasSAR = true; break;
				case "RCL": hasRCL = true; break;
				case "RCR": hasRCR = true; break;
			}
		}

		// SHL + RCL = left shift
		if (hasSHL && hasRCL) return "aFNalshl";
		// SAR + RCR = arithmetic (signed) right shift
		if (hasSAR && hasRCR) return "aFNalsar";
		// SHR + RCR = logical (unsigned) right shift
		if (hasSHR && hasRCR) return "aFNalshr";

		return null;
	}

	/**
	 * Heuristic: identify likely long-arithmetic runtime functions by their
	 * structural properties. Analyzes parameter count, function body size,
	 * and call relationships to identify __aNlmul, __aNldiv, __aNlrem.
	 *
	 * This works on unnamed functions in freshly imported binaries.
	 */
	private Map<Function, String> identifyByStructure(FunctionManager funcManager) {
		Map<Function, String> identified = new LinkedHashMap<>();
		Function mulCandidate = null;
		Function divCandidate = null;
		Function remCandidate = null;
		List<Function> fourParamFuncs = new ArrayList<>();

		// Collect all unnamed functions with 4 word-sized parameters
		FunctionIterator iter = funcManager.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function func = iter.next();
			if (!func.getName().startsWith("FUN_")) continue;

			Parameter[] params = func.getParameters();
			if (params.length != 4) continue;

			// All params must be 2 bytes (word)
			boolean allWord = true;
			for (Parameter p : params) {
				if (p.getLength() != 2) { allWord = false; break; }
			}
			if (!allWord) continue;

			// Count references to this function (how many call sites)
			int callCount = 0;
			var refs = currentProgram.getReferenceManager()
				.getReferencesTo(func.getEntryPoint());
			while (refs.hasNext()) {
				refs.next();
				callCount++;
			}

			// Runtime helpers are called from multiple sites
			if (callCount < 2) continue;

			fourParamFuncs.add(func);
		}

		// Now classify: smallest body = mul, largest = div or rem
		// __aNlmul is typically 30-50 bytes, __aNldiv/rem are 100-200 bytes
		for (Function func : fourParamFuncs) {
			long bodySize = func.getBody().getNumAddresses();

			if (bodySize < 80) {
				// Small function with 4 word params called multiple times = likely __aNlmul
				if (mulCandidate == null || bodySize < mulCandidate.getBody().getNumAddresses()) {
					mulCandidate = func;
				}
			}
		}

		// For div/rem: they're the larger functions. __aNlrem typically calls __aNldiv
		// or is structured similarly. We distinguish by: __aNldiv has NO calls to
		// other 4-param functions, while __aNlrem calls __aNldiv.
		List<Function> largeFuncs = new ArrayList<>();
		for (Function func : fourParamFuncs) {
			if (func == mulCandidate) continue;
			long bodySize = func.getBody().getNumAddresses();
			if (bodySize >= 80) {
				largeFuncs.add(func);
			}
		}

		if (largeFuncs.size() >= 2) {
			// Check which one calls the other
			for (Function f : largeFuncs) {
				for (Function g : largeFuncs) {
					if (f == g) continue;
					// Does f call g?
					if (callsFunction(f, g)) {
						// f calls g: f is __aNlrem (calls __aNldiv), g is __aNldiv
						remCandidate = f;
						divCandidate = g;
						break;
					}
				}
				if (divCandidate != null) break;
			}

			// If neither calls the other, use address ordering:
			// MSC links __aNldiv before __aNlrem
			if (divCandidate == null && largeFuncs.size() == 2) {
				Function first = largeFuncs.get(0);
				Function second = largeFuncs.get(1);
				if (first.getEntryPoint().compareTo(second.getEntryPoint()) < 0) {
					divCandidate = first;
					remCandidate = second;
				} else {
					divCandidate = second;
					remCandidate = first;
				}
			}
		} else if (largeFuncs.size() == 1) {
			// Only one large function — could be either div or rem.
			// Default to div since it's more common standalone.
			divCandidate = largeFuncs.get(0);
		}

		if (mulCandidate != null) identified.put(mulCandidate, "aNlmul");
		if (divCandidate != null) identified.put(divCandidate, "aNldiv");
		if (remCandidate != null) identified.put(remCandidate, "aNlrem");

		return identified;
	}

	/**
	 * Check if function 'caller' contains a call to function 'callee'.
	 */
	private boolean callsFunction(Function caller, Function callee) {
		var refs = currentProgram.getReferenceManager()
			.getReferencesTo(callee.getEntryPoint());
		while (refs.hasNext()) {
			var ref = refs.next();
			if (caller.getBody().contains(ref.getFromAddress())) {
				return true;
			}
		}
		return false;
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
		int identifiedCount = 0;

		// Phase 1: Try to identify unnamed functions by byte patterns
		Memory memory = currentProgram.getMemory();
		FunctionIterator allFunctions = funcManager.getFunctions(true);
		while (allFunctions.hasNext() && !monitor.isCancelled()) {
			Function func = allFunctions.next();
			String name = func.getName();

			// Skip already-named functions
			if (!name.startsWith("FUN_")) {
				continue;
			}

			String matched = matchBytePattern(func, memory);
			if (matched != null) {
				String newName = "__" + matched;
				try {
					func.setName(newName, SourceType.ANALYSIS);
					println("Identified by bytes: " + name + " -> " + newName +
						" at " + func.getEntryPoint());
					identifiedCount++;
				} catch (Exception e) {
					println("  Warning: could not rename " + name + ": " + e.getMessage());
				}
			}
		}

		if (identifiedCount > 0) {
			println("Identified " + identifiedCount + " function(s) by byte patterns.");
		}

		// Phase 1b: Structural identification for remaining unnamed functions
		// First: identify mul/div/rem (4 word params)
		Map<Function, String> structMatches = identifyByStructure(funcManager);
		for (Map.Entry<Function, String> entry : structMatches.entrySet()) {
			Function func = entry.getKey();
			String baseName = entry.getValue();
			// Only rename if still unnamed
			if (func.getName().startsWith("FUN_")) {
				String newName = "__" + baseName;
				try {
					func.setName(newName, SourceType.ANALYSIS);
					println("Identified by structure: " + func.getName() + " -> " + newName +
						" at " + func.getEntryPoint() +
						" (body=" + func.getBody().getNumAddresses() + " bytes)");
					identifiedCount++;
				} catch (Exception e) {
					println("  Warning: could not rename: " + e.getMessage());
				}
			}
		}

		// Phase 1c: Structural identification for shift helpers (3 word params)
		Map<Function, String> shiftMatches = identifyShiftHelpers(funcManager);
		for (Map.Entry<Function, String> entry : shiftMatches.entrySet()) {
			Function func = entry.getKey();
			String baseName = entry.getValue();
			if (func.getName().startsWith("FUN_")) {
				String newName = "__" + baseName;
				try {
					func.setName(newName, SourceType.ANALYSIS);
					println("Identified shift helper: " + func.getName() + " -> " + newName +
						" at " + func.getEntryPoint() +
						" (body=" + func.getBody().getNumAddresses() + " bytes)");
					identifiedCount++;
				} catch (Exception e) {
					println("  Warning: could not rename: " + e.getMessage());
				}
			}
		}

		// Phase 2: Apply signatures to all named functions (including newly identified ones)
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
				// Set calling convention (skip for return-type-only shift helpers)
				if (sigType != SigType.RETURN_LONG_ONLY &&
					sigType != SigType.RETURN_ULONG_ONLY) {
					try {
						func.setCallingConvention(CC_CDECL);
					}
					catch (Exception e) {
						println("  Warning: could not set calling convention: " + e.getMessage());
					}
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
					case RETURN_LONG_ONLY:
					case RETURN_ULONG_ONLY:
						// Only fix the return type — don't touch params or calling convention.
						// These are register-based functions (val in DX:AX, count in CL).
						// Setting custom storage causes register pollution in callers.
						retType = (sigType == SigType.RETURN_LONG_ONLY) ? longType : ulongType;
						func.setReturnType(retType, SourceType.USER_DEFINED);
						println("  Applied return type: " + retType.getDisplayName() + " " + name + "(...)");
						fixedCount++;
						continue;
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

		println("\nDone. Identified " + identifiedCount + " by byte patterns, fixed " +
			fixedCount + " signature(s).");
	}

	/**
	 * Try to match a function's entry bytes against known MSC runtime patterns.
	 * Returns the base name (e.g. "aNlmul") if matched, null otherwise.
	 */
	private String matchBytePattern(Function func, Memory memory) {
		Address entry = func.getEntryPoint();

		for (BytePattern pattern : BYTE_PATTERNS) {
			try {
				byte[] funcBytes = new byte[pattern.bytes.length];
				int bytesRead = memory.getBytes(entry, funcBytes);
				if (bytesRead < pattern.bytes.length) continue;

				boolean match = true;
				for (int i = 0; i < pattern.bytes.length; i++) {
					if ((funcBytes[i] & pattern.mask[i]) != (pattern.bytes[i] & pattern.mask[i])) {
						match = false;
						break;
					}
				}
				if (match) {
					// Verify: also check the signature type exists
					if (FUNC_SIGS.containsKey(pattern.name)) {
						return pattern.name;
					}
				}
			} catch (MemoryAccessException e) {
				// Skip functions in non-readable memory
			}
		}
		return null;
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
