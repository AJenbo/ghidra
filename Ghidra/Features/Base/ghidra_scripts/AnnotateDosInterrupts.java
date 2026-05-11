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
//Annotates DOS interrupt calls (INT 21h, INT 10h, INT 1Ah, INT 33h) with
//descriptive comments based on the AH/AX register value set before the interrupt.
//The script scans all instructions, finds INT instructions, looks backward to
//determine the function number loaded into AH, and adds a PRE comment describing
//the DOS/BIOS function being invoked.
//@category Analysis

import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class AnnotateDosInterrupts extends GhidraScript {

	private static final int MAX_LOOKBACK = 10;

	private Map<Integer, Map<Integer, String>> interruptFunctions;

	private void initInterruptFunctions() {
		interruptFunctions = new HashMap<>();

		// INT 21h - DOS services
		Map<Integer, String> int21 = new HashMap<>();
		int21.put(0x00, "INT 21h/AH=00h: Terminate program");
		int21.put(0x01, "INT 21h/AH=01h: Read character with echo");
		int21.put(0x02, "INT 21h/AH=02h: Write character");
		int21.put(0x09, "INT 21h/AH=09h: Write string (DS:DX)");
		int21.put(0x0A, "INT 21h/AH=0Ah: Buffered input");
		int21.put(0x0C, "INT 21h/AH=0Ch: Flush buffer and read");
		int21.put(0x19, "INT 21h/AH=19h: Get current drive");
		int21.put(0x1A, "INT 21h/AH=1Ah: Set DTA address");
		int21.put(0x25, "INT 21h/AH=25h: Set interrupt vector");
		int21.put(0x2C, "INT 21h/AH=2Ch: Get system time");
		int21.put(0x30, "INT 21h/AH=30h: Get DOS version");
		int21.put(0x35, "INT 21h/AH=35h: Get interrupt vector");
		int21.put(0x3C, "INT 21h/AH=3Ch: Create file");
		int21.put(0x3D, "INT 21h/AH=3Dh: Open file");
		int21.put(0x3E, "INT 21h/AH=3Eh: Close file");
		int21.put(0x3F, "INT 21h/AH=3Fh: Read file");
		int21.put(0x40, "INT 21h/AH=40h: Write file");
		int21.put(0x41, "INT 21h/AH=41h: Delete file");
		int21.put(0x42, "INT 21h/AH=42h: Seek (lseek)");
		int21.put(0x43, "INT 21h/AH=43h: Get/set file attributes");
		int21.put(0x44, "INT 21h/AH=44h: IOCTL");
		int21.put(0x48, "INT 21h/AH=48h: Allocate memory");
		int21.put(0x49, "INT 21h/AH=49h: Free memory");
		int21.put(0x4A, "INT 21h/AH=4Ah: Resize memory block");
		int21.put(0x4C, "INT 21h/AH=4Ch: Exit with return code");
		int21.put(0x56, "INT 21h/AH=56h: Rename file");
		int21.put(0x57, "INT 21h/AH=57h: Get/set file date/time");
		interruptFunctions.put(0x21, int21);

		// INT 10h - BIOS video services
		Map<Integer, String> int10 = new HashMap<>();
		int10.put(0x00, "INT 10h/AH=00h: Set video mode");
		int10.put(0x02, "INT 10h/AH=02h: Set cursor position");
		int10.put(0x0E, "INT 10h/AH=0Eh: Write character in teletype mode");
		int10.put(0x0F, "INT 10h/AH=0Fh: Get video mode");
		int10.put(0x10, "INT 10h/AH=10h: Set palette");
		int10.put(0x11, "INT 10h/AH=11h: Character generator");
		int10.put(0x12, "INT 10h/AH=12h: Alternate select");
		int10.put(0x13, "INT 10h/AH=13h: Write string");
		interruptFunctions.put(0x10, int10);

		// INT 1Ah - BIOS timer services
		Map<Integer, String> int1a = new HashMap<>();
		int1a.put(-1, "INT 1Ah: BIOS timer services");
		interruptFunctions.put(0x1A, int1a);

		// INT 33h - Mouse driver
		Map<Integer, String> int33 = new HashMap<>();
		int33.put(-1, "INT 33h: Mouse driver");
		interruptFunctions.put(0x33, int33);
	}

	@Override
	public void run() throws Exception {
		initInterruptFunctions();

		Listing listing = currentProgram.getListing();
		int annotationCount = 0;
		int skippedCount = 0;
		int totalIntFound = 0;

		InstructionIterator instructions = listing.getInstructions(true);
		while (instructions.hasNext() && !monitor.isCancelled()) {
			Instruction inst = instructions.next();
			String mnemonic = inst.getMnemonicString();

			if (!"INT".equalsIgnoreCase(mnemonic)) {
				continue;
			}

			// Get the interrupt number from the operand
			int intNum = -1;
			try {
				Object[] opObjects = inst.getOpObjects(0);
				if (opObjects.length > 0) {
					if (opObjects[0] instanceof ghidra.program.model.scalar.Scalar) {
						intNum = (int) ((ghidra.program.model.scalar.Scalar) opObjects[0])
								.getUnsignedValue();
					}
				}
			}
			catch (Exception e) {
				continue;
			}

			if (intNum < 0 || !interruptFunctions.containsKey(intNum)) {
				continue;
			}

			totalIntFound++;

			// Skip if a PRE comment already exists
			String existing = inst.getComment(CommentType.PRE);
			if (existing != null && !existing.isEmpty()) {
				skippedCount++;
				continue;
			}

			Map<Integer, String> funcMap = interruptFunctions.get(intNum);
			String comment = null;

			// For interrupts with a default description (no AH lookup needed)
			if (funcMap.containsKey(-1) && funcMap.size() == 1) {
				comment = funcMap.get(-1);
			}
			else {
				// Look backward for MOV AH, imm8 or MOV AX, imm16
				int ahValue = findAHValue(inst);
				if (ahValue >= 0) {
					comment = funcMap.get(ahValue);
					if (comment == null) {
						comment = String.format("INT %02Xh/AH=%02Xh: Unknown function", intNum,
							ahValue);
					}
				}
				else {
					comment = String.format("INT %02Xh: Could not determine AH value", intNum);
				}
			}

			inst.setComment(CommentType.PRE, comment);
			annotationCount++;
		}

		println("=== DOS Interrupt Annotation Summary ===");
		println("Total INT instructions found (matching targets): " + totalIntFound);
		println("Annotations added: " + annotationCount);
		println("Skipped (existing comment): " + skippedCount);
	}

	/**
	 * Looks backward from the given INT instruction (up to MAX_LOOKBACK instructions)
	 * to find a MOV AH, imm8 or MOV AX, imm16 instruction, and returns the AH value.
	 *
	 * @param intInst the INT instruction to search backward from
	 * @return the AH value (0-255), or -1 if not found
	 */
	private int findAHValue(Instruction intInst) {
		Instruction current = intInst;
		for (int i = 0; i < MAX_LOOKBACK; i++) {
			current = current.getPrevious();
			if (current == null) {
				break;
			}

			String mnemonic = current.getMnemonicString();
			if (!"MOV".equalsIgnoreCase(mnemonic)) {
				continue;
			}

			// Check number of operands
			if (current.getNumOperands() < 2) {
				continue;
			}

			String op0Str = current.getDefaultOperandRepresentation(0);
			Object[] op1Objects = current.getOpObjects(1);

			if (op1Objects.length == 0) {
				continue;
			}

			if (!(op1Objects[0] instanceof ghidra.program.model.scalar.Scalar)) {
				continue;
			}

			long immValue =
				((ghidra.program.model.scalar.Scalar) op1Objects[0]).getUnsignedValue();

			// MOV AH, imm8
			if ("AH".equalsIgnoreCase(op0Str)) {
				return (int) (immValue & 0xFF);
			}

			// MOV AX, imm16 - AH is the high byte
			if ("AX".equalsIgnoreCase(op0Str)) {
				return (int) ((immValue >> 8) & 0xFF);
			}

			// MOV EAX, imm32 - AH is bits 8-15
			if ("EAX".equalsIgnoreCase(op0Str)) {
				return (int) ((immValue >> 8) & 0xFF);
			}
		}
		return -1;
	}
}
