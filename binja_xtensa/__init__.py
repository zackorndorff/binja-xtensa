"""
Binary Ninja Xtensa (and ESP8266) support

This package offers several features:

Xtensa (little-endian):
    * correct length decoding for nearly all instructions
    * correct mnemonic decoding for nearly all instructions
    * fully correct disassembly for most instructions you'll see. In some places
      there are comments documenting skipped features. The disassembler took over
      10 hours to write, and the firmware I'm looking at didn't have a lot of
      floating point instructions :)
    * objdump-equivalent disassembly for all the instructions in the firmware I
      had laying around (complete with a pytest scaffolding to test this)
    * lifting to BNIL for 80+ of the most common instructions. This is enough
      for useful decompilation, courtesy of the Binary Ninja core.
    * a CallingConvention that matches what the documentation says GCC does.
      After adding this and setting it default, Binary Ninja started recognizing
      a good amount of function arguments.
    * declared support for whatever ELF architecture the ESP8266 tools in
      platformio generate... so if you open up an elf it builds you, it should
      recognize the architecture.

ESP8266-specific:
    * a BinaryView implementation that attempts to detect and load ESP8266
      firmware dumps. The current implementation is hacky, but it's able to
      examine multiple .bin dumps I've obtained through different methods.

      * These dumps sometimes contain multiple binaries (namely, a bootloader
        plus user code. I've added a "Open with Options" option to choose which
        of the binaries you want to look at. By default, it tries to pick the
        last binary containing parsed segments.

What it doesn't yet do:
    * anything with windowed registers
    * anything with the optional vector unit
    * disassemble and lift most of the boolean instructions
    * lift most floating point instructions
    * deal with special registers (I figure you might as well look at the asm
      for that anyway)
    * help you find `main` in a raw binary :)

I've abused Python metaprogramming throughout, so it should be possible to fix
each of the above inaccuracies on a per-instruction basis if the need arises.
I've attempted to document how that works.
"""

from binaryninja import (Architecture, BinaryViewType, CallingConvention,
                         IntrinsicInfo, InstructionInfo, InstructionTextToken,
                         RegisterInfo, log)
from binaryninja.enums import (BranchType, Endianness, FlagRole,
                               LowLevelILFlagCondition)

from .instruction import Instruction
from .disassembly import disassemble_instruction
from .lifter import lift
from .binaryview import ESPFirmware


__all__ = ['XtensaLE']


class XtensaLE(Architecture):
    name = 'xtensa'
    endianness = Endianness.LittleEndian

    default_int_size = 4
    address_size = 4
    max_instr_length = 3

    # Uses for regs are from "CALL0 Register Usage and Stack Layout (8.1.2)"
    link_reg = 'a0'
    stack_pointer = 'a1'
    regs = {
        'a0': RegisterInfo("a0", 4, 0), # ret addr
        'a1': RegisterInfo("a1", 4, 0), # sp (callee-saved)
        'a2': RegisterInfo("a2", 4, 0), # arg1
        'a3': RegisterInfo("a3", 4, 0), # arg2
        'a4': RegisterInfo("a4", 4, 0), # arg3
        'a5': RegisterInfo("a5", 4, 0), # arg4
        'a6': RegisterInfo("a6", 4, 0), # arg5
        'a7': RegisterInfo("a7", 4, 0), # arg6
        'a8': RegisterInfo("a8", 4, 0), # static chain (see section 8.1.8)
        'a9': RegisterInfo("a9", 4, 0),
        'a10': RegisterInfo("a10", 4, 0),
        'a11': RegisterInfo("a11", 4, 0),
        'a12': RegisterInfo("a12", 4, 0), # callee-saved
        'a13': RegisterInfo("a13", 4, 0), # callee-saved
        'a14': RegisterInfo("a14", 4, 0), # callee-saved
        'a15': RegisterInfo("a15", 4, 0), # optional stack-frame pointer
        'sar': RegisterInfo("sar", 1, 0), # Shift Address Register: Not a GPR
    }

    # Do we have flags?
    flags = {}
    flag_roles = {}
    flag_write_types = {}
    flags_written_by_flag_write_type = {}
    flags_required_for_flag_condition = {}

    intrinsics = {
        "memw": IntrinsicInfo([], []),
        "isync": IntrinsicInfo([], []),
    }

    def _decode_instruction(self, data, addr):
        insn = None
        try:
            insn = Instruction.decode(data)
        except:
            pass
        return insn

    def get_instruction_info(self, data, addr):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        result = InstructionInfo()
        result.length = insn.length
        if insn.length > 3 or insn.length < 0:
            raise Exception("Somehow we got here without setting length")

        # Add branches
        if insn.mnem in ["RET", "RET.N"]:
            result.add_branch(BranchType.FunctionReturn)

        # Section 3.8.4 "Jump and Call Instructions
        elif insn.mnem in ["J"]:
            result.add_branch(BranchType.UnconditionalBranch,
                              insn.target_offset(addr))
        elif insn.mnem in ["JX"]:
            result.add_branch(BranchType.IndirectBranch)

        elif insn.mnem in ["CALL0", "CALL4", "CALL8", "CALL12"]:
            result.add_branch(BranchType.CallDestination,
                              insn.target_offset(addr))
        elif insn.mnem in ["CALLX0", "CALLX4", "CALLX8", "CALLX12"]:
            pass
            #result.add_branch(BranchType.IndirectBranch)

        elif insn.mnem in ["SYSCALL"]:
            result.add_branch(BranchType.SystemCall)

        elif insn.mnem.replace(".", "_") in [k for k in Instruction._target_offset_map.keys() if
                           k.startswith("B")]: # lol
            result.add_branch(BranchType.TrueBranch, insn.target_offset(addr))
            result.add_branch(BranchType.FalseBranch, addr + insn.length)

        return result

    def get_instruction_text(self, data, addr):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        text = disassemble_instruction(insn, addr)
        return text, insn.length

    def get_instruction_low_level_il(self, data, addr, il):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        return lift(insn, addr, il)


class XtensaCall0CallingConvention(CallingConvention):
    # a0 is dubiously caller saved... it's the ret addr / link register
    caller_saved_regs = ["a0", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9",
                         "a10", "a11"]
    int_arg_regs = ["a2", "a3", "a4", "a5", "a6", "a7"]
    int_return_reg = "a2"
    high_int_return_reg = "a3"


def register_stuff():
    XtensaLE.register()

    # Register ourselves with the ELF loader
    BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian,
                                        Architecture['xtensa'])
    arch = Architecture['xtensa']
    arch.register_calling_convention(XtensaCall0CallingConvention(arch, "default"))

    # If we register on the Architecture's standalone platform, it seems to use our
    # calling convention without showing __convention("default") on every function
    esp_plat = arch.standalone_platform
    esp_plat.default_calling_convention = arch.calling_conventions['default']

    ESPFirmware.register()


register_stuff()
