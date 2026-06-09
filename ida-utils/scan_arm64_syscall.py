"""
ARM64 ntdll Syscall Stub Scanner (IDA Python)

Iterates through Nt*/Zw* functions in the export directory, scanning a fixed window 
near the entry point to match signatures, extract, and classify Syscall Stub patterns:
1. direct_svc    : Directly executes `SVC #imm` (Direct System Call).
2. w8_before_svc : Loads SSN (System Service Number) via `MOV/MOVZ W8/X8, #imm` before executing `SVC`.
3. no_svc        : No trap instruction found within the scanning window.

Used for rapid reverse engineering and comparing syscall mechanisms across different ARM64 ntdll versions.
"""

import idautils
import idc
import ida_bytes

try:
    import ida_lines
except Exception:
    ida_lines = None

# ARM64 RET instruction machine code
ARM64_RET = 0xD65F03C0


def clean_line(line):
    """Strips color and formatting control characters from IDA disassembly text."""
    if line is None:
        return ""
    if ida_lines:
        return ida_lines.tag_remove(line)
    return line


def is_arm64_svc(instr):
    """Matches `SVC #imm` (Opcode: 0xD4000001, Mask: 0xFFE0001F)."""
    return (instr & 0xFFE0001F) == 0xD4000001


def get_svc_imm(instr):
    """Parses the 16-bit immediate value (extracts the SSN) from the SVC instruction."""
    return (instr >> 5) & 0xFFFF


def is_arm64_ret(instr):
    """Strictly matches the `RET` instruction."""
    return instr == ARM64_RET


def is_movz_w8_imm(instr):
    """Matches `MOVZ W8, #imm` (W8 is typically used to hold the SSN in ARM64)."""
    return (instr & 0xFFE0001F) == 0x52800008


def is_movz_x8_imm(instr):
    """Matches `MOVZ X8, #imm` (Compatible with 64-bit wide X8 register argument passing)."""
    return (instr & 0xFFE0001F) == 0xD2800008


def is_text_mov_w8_or_x8_imm(ea):
    """
    Text-matching fallback: Handles aliasing in the IDA disassembly engine.
    
    IDA often simplifies `MOVZ` as a generic `MOV` pseudo-instruction, causing 
    machine-code matches to miss. This acts as a fallback by checking the text 
    operands for target registers (w8/x8) and immediate prefixes (#).
    """
    mnem = idc.print_insn_mnem(ea).lower()
    op0 = idc.print_operand(ea, 0).lower().replace(" ", "")
    op1 = idc.print_operand(ea, 1).lower().replace(" ", "")

    if mnem not in ("mov", "movz"):
        return False

    if op0 not in ("w8", "x8"):
        return False

    if not op1.startswith("#"):
        return False

    return True


def scan_ntzw_export(name, ea, max_scan_size=0x30):
    """
    Performs a sliding-window scan on a single export function to extract the Syscall signature.
    
    Returned fields:
    - type            : The stub pattern type.
    - svc_ea/imm/line : Address, SSN, and disassembly text of the SVC instruction.
    - mov_ea/line     : Address and text of the closest W8/X8 immediate assignment before SVC.
    - next_is_ret     : True if the instruction immediately following SVC is RET 
                        (useful for detecting hooks or custom handling).
    """
    found_mov_w8 = False
    mov_line = ""
    mov_ea = 0

    # ARM64 instructions are fixed 4-byte length, so the step is 4.
    for off in range(0, max_scan_size, 4):
        cur = ea + off
        instr = ida_bytes.get_dword(cur)
        line = clean_line(idc.generate_disasm_line(cur, 0))

        # Prioritize strict machine-code matching for MOVZ; fallback to IDA text matching if it fails.
        if is_movz_w8_imm(instr) or is_movz_x8_imm(instr):
            found_mov_w8 = True
            mov_ea = cur
            mov_line = line
        elif is_text_mov_w8_or_x8_imm(cur):
            found_mov_w8 = True
            mov_ea = cur
            mov_line = line

        # Hit a trap instruction, finalize current scan results.
        if is_arm64_svc(instr):
            svc_imm = get_svc_imm(instr)
            next_instr = ida_bytes.get_dword(cur + 4)
            next_is_ret = is_arm64_ret(next_instr)

            if found_mov_w8:
                return {
                    "type": "w8_before_svc",
                    "svc_ea": cur,
                    "svc_imm": svc_imm,
                    "svc_line": line,
                    "mov_ea": mov_ea,
                    "mov_line": mov_line,
                    "next_is_ret": next_is_ret,
                }

            return {
                "type": "direct_svc",
                "svc_ea": cur,
                "svc_imm": svc_imm,
                "svc_line": line,
                "mov_ea": None,
                "mov_line": None,
                "next_is_ret": next_is_ret,
            }

        # Stop scanning early if a RET instruction is encountered.
        # Syscall stubs are typically very short. Scanning past a RET often leads 
        # to false matches in adjacent functions or padding bytes.
        if is_arm64_ret(instr):
            break

    # The entire window was scanned (or truncated by RET) without finding an SVC.
    return {
        "type": "no_svc",
        "svc_ea": None,
        "svc_imm": None,
        "svc_line": None,
        "mov_ea": None,
        "mov_line": None,
        "next_is_ret": False,
    }


def main():
    """Entry point: Iterates over the export table, runs heuristic scanning, and prints the statistical distribution."""
    total_exports = 0
    total_ntzw_exports = 0

    direct_svc_count = 0
    w8_before_svc_count = 0
    no_svc_count = 0

    direct_svc_samples = []
    w8_before_svc_samples = []
    no_svc_samples = []

    print("========== ARM64 ntdll export syscall statistics ==========")

    for index, ordinal, ea, name in idautils.Entries():
        total_exports += 1

        if not name:
            continue

        # Focus only on Native APIs
        if not (name.startswith("Nt") or name.startswith("Zw")):
            continue

        total_ntzw_exports += 1

        result = scan_ntzw_export(name, ea)

        if result["type"] == "direct_svc":
            direct_svc_count += 1
            if len(direct_svc_samples) < 20:
                direct_svc_samples.append((name, result))

        elif result["type"] == "w8_before_svc":
            w8_before_svc_count += 1
            w8_before_svc_samples.append((name, result))

        else:
            no_svc_count += 1
            if len(no_svc_samples) < 20:
                no_svc_samples.append((name, result))

    # Print statistical report
    print("\n========== Summary ==========")
    print("Total exports                         : %d" % total_exports)
    print("Nt/Zw exports scanned                 : %d" % total_ntzw_exports)
    print("Nt/Zw direct SVC #imm                 : %d" % direct_svc_count)
    print("Nt/Zw MOV W8/X8 before SVC            : %d" % w8_before_svc_count)
    print("Nt/Zw no SVC in scanned range         : %d" % no_svc_count)

    print("\nCheck:")
    print("direct_svc + w8_before_svc + no_svc   : %d" %
          (direct_svc_count + w8_before_svc_count + no_svc_count))

    # Print Direct SVC samples
    print("\n========== Direct SVC #imm samples, max 20 ==========")
    for name, r in direct_svc_samples:
        print("[SVC   ] %-45s  0x%X  ssn=0x%X  %s  ; next=%s" %
              (
                  name,
                  r["svc_ea"],
                  r["svc_imm"],
                  r["svc_line"],
                  "RET" if r["next_is_ret"] else "not RET"
              ))

    # Print W8 -> SVC samples
    print("\n========== MOV W8/X8 before SVC samples ==========")
    if not w8_before_svc_samples:
        print("No MOV W8/X8 before SVC pattern found.")
    else:
        for name, r in w8_before_svc_samples:
            print("[W8->SVC] %-45s" % name)
            print("    MOV EA : 0x%X" % r["mov_ea"])
            print("    MOV    : %s" % r["mov_line"])
            print("    SVC EA : 0x%X" % r["svc_ea"])
            print("    SVC IMM: 0x%X" % r["svc_imm"])
            print("    SVC    : %s" % r["svc_line"])
            print("    NEXT   : %s" % ("RET" if r["next_is_ret"] else "not RET"))
            print("")

    # Print no-SVC samples (could be normal exports, heavily obfuscated, or redirected)
    print("\n========== No SVC samples, max 20 ==========")
    for name, r in no_svc_samples:
        print("[NO SVC] %-45s" % name)

    print("\n========== Finished ==========")


if __name__ == "__main__":
    main()