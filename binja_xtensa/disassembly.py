"""
Xtensa disassembly rendering

The idea is instruction.py handles instruction decoding, then to get
human-readable disassembly, we call disassemble_instruction from this file.

The lifter should *not* need the information in this file. If it does, move that
computation into the decoder.
"""
from binaryninja import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .instruction import Instruction, InstructionType, sign_extend

# Helpers to generate Binary Ninja InstructionTextTokens, since the names are
# so long. We also do some cosmetic transformations of the encoded immediates
# here.
def _get_space():
    return InstructionTextToken(InstructionTextTokenType.TextToken, "    ")

def _get_comma():
    return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", ")

def _get_reg_tok(reg_name):
    return InstructionTextToken(InstructionTextTokenType.RegisterToken,
                                reg_name)

def _get_imm8_tok(val):
    return InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                str(val), val, size=1)

def _get_imm32_tok(val):
    return InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                str(val), val, size=4)

def _get_imm8(insn, _):
    val = insn.imm8
    return _get_imm8_tok(val)

def _get_simm8(insn, _):
    val = sign_extend(insn.imm8, 8)
    return _get_imm8_tok(val)

def _get_simm8_s8(insn, _):
    val = sign_extend(insn.imm8, 8)
    val <<= 8
    return InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                str(val), val, size=4)

def _get_addi_n_imm(insn, _):
    val = insn.inline0(_)
    return InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                str(val), val, size=4)

def _get_possible_address_token(addr):
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken,
                                hex(addr)[2:], addr, size=4)
def _get_target_offset(insn, addr):
    val = insn.target_offset(addr)
    return _get_possible_address_token(val)

def _get_mem_offset(insn, addr):
    val = insn.mem_offset(addr)
    return _get_possible_address_token(val)

def _get_b4const(insn, _):
    val = insn.b4const()
    return InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                str(val), val, size=4)

def _get_b4constu(insn, _):
    val = insn.b4constu()
    return InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                str(val), val, size=4)

# I wanted the mechanical instruction -> disassembly process to be as easy to
# write as possible. Thus, it's structured so I can take the example instruction
# out of the manual and type it in here with slight modification, and it'll
# mostly work. Then I just have to check for nonobvious differences and move on
# to the next instruction.

# This table defines the logic that backs up each of those things from the
# manual.

# each of these should return a binja InstructionTextToken
_disassembly_fmts = {
    "ar": lambda insn, _: _get_reg_tok("a" + str(insn.r)),
    "as": lambda insn, _: _get_reg_tok("a" + str(insn.s)),
    "at": lambda insn, _: _get_reg_tok("a" + str(insn.t)),

    "fr": lambda insn, _: _get_reg_tok("f" + str(insn.r)),
    "fs": lambda insn, _: _get_reg_tok("f" + str(insn.s)),
    "ft": lambda insn, _: _get_reg_tok("f" + str(insn.t)),

    "bt": lambda insn, _: _get_reg_tok("b" + str(insn.t)),
    "bs": lambda insn, _: _get_reg_tok("b" + str(insn.s)),
    "br": lambda insn, _: _get_reg_tok("b" + str(insn.r)),

    "s": lambda insn, _: _get_imm8_tok(insn.s),
    "t": lambda insn, _: _get_imm8_tok(insn.t),

    "imm8": _get_imm8,
    "simm8": _get_simm8,
    "simm8_s8": _get_simm8_s8, # simm8 shifted left by 8

    "target_offset": _get_target_offset,
    "mem_offset": _get_mem_offset,

    "b4const": _get_b4const,
    "b4constu": _get_b4constu,

    # Oddball
    # Probably should have been an inline0... but I hadn't hacked that in yet
    # when I dealt with ADDI.N
    "addi_n_imm": _get_addi_n_imm,
}
def _dis(fmt_str, *args):
    """Helper to create disassembly functions for different formats
    
    See below to see how it's used.
    """
    def inner(insn, addr):
        fmts = fmt_str.split()
        tokens = []
        tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                         insn.mnem))
        tokens.append(_get_space())
        for idx, fmt in enumerate(fmts):
            if idx > 0:
                tokens.append(_get_comma())

            # For one-off encodings, I wanted a way to specify that in the _dis
            # invocation for the instruction. These "inline" encodings are
            # similar to the ones in the decoder, but they're distinct at a
            # programmatic level; they just share a name and are used together
            # :)
            if fmt.startswith("inline"):
                tok_idx = int(fmt[len("inline"):])
                try:
                    token_func = args[tok_idx]
                except IndexError:
                    token_func = getattr(insn, fmt)
            else:
                token_func = _disassembly_fmts[fmt]

            tokens.append(token_func(insn, addr))
        return tokens
    return inner

def disassemble_instruction(insn, addr):
    """Return Binary Ninja InstructionTextTokens for instruction

    So to disassemble an instruction, we call Instruction.decode with the bytes,
    then we call disassemble_instruction with the returned instruction and the
    address it's loaded at.
    """
    func = None
    try:
        func = globals()["_disassemble_" + insn.mnem.replace(".", "_")]
    except KeyError:
        pass

    if func:
        return func(insn, addr)
    if insn.instruction_type == InstructionType.RRR:
        return _disassemble_rrr(insn, addr)
    elif insn.instruction_type == InstructionType.RRRN:
        return _disassemble_rrrn(insn, addr)
    elif insn.instruction_type == InstructionType.RRI8:
        return _disassemble_rri8(insn, addr)
    else:
        # Fallback for when we don't have a fallback for a particular
        # instruction type.
        # If I had to rewrite this, I'd remove the type-fallbacks and just show
        # a warning in fallback cases, as we do here.
        text = []
        text.append(InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                         insn.mnem))
        text.append(_get_space())
        text.append(InstructionTextToken(InstructionTextTokenType.TextToken,
                                     "unimplemented_disass"))
        return text

def tokens_to_text(token_list):
    """Convert a list of binja tokens to plain text

    Mostly useful for testing
    """
    return ''.join([tok.text for tok in token_list])

def _disassemble_RSR(insn, addr):
    mnem = insn.mnem + "." + insn.get_sr_name()
    tokens = []
    tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken,
                                     mnem))
    tokens.append(_get_space())
    fmts = ["at"]
    for idx, fmt in enumerate(fmts):
        if idx > 0:
            tokens.append(_get_comma())

        if fmt.startswith("inline"):
            tok_idx = int(fmt[len("inline"):])
            token_func = args[tok_idx]
        else:
            token_func = _disassembly_fmts[fmt]

        tokens.append(token_func(insn, addr))
    return tokens

_disassemble_WSR = _disassemble_XSR = _disassemble_RSR

# As I mentioned in the decoding code, instruction formats aren't too useful in
# Xtensa... but we do fall back to these for a few simple instructions. It's
# almost easier to list an instruction below than it is to verify the default is
# correct.
_disassemble_rrr = _dis("ar as at")
_disassemble_rrrn = _dis("ar as at")
_disassemble_rri8 = _dis("at as simm8")

# Overrides for exceptions to the instruction type
_disassemble_ABS = _dis("ar at")
_disassemble_ABS_S = _dis("fr fs")
_disassemble_ADD_S = _dis("fr fs ft")
_disassemble_ADDI_N = _dis("ar as addi_n_imm")
_disassemble_ADDMI = _dis("at as simm8_s8")
_disassemble_ALL4 = _dis("bt bs")
_disassemble_ALL8 = _dis("bt bs")
_disassemble_ANDB = _dis("br bs bt")
_disassemble_ANDBC = _dis("br bs bt")
_disassemble_ANY4 = _dis("bt bs")
_disassemble_ANY8 = _dis("bt bs")

_disassemble_BALL = _dis("as at target_offset")
_disassemble_BANY = _dis("as at target_offset")
_disassemble_BBC = _dis("as at target_offset")
_disassemble_BBCI = _dis("as inline0 target_offset",
                         lambda insn, _: _get_imm8_tok(insn.inline0(_)))
_disassemble_BBS = _dis("as at target_offset")

_disassemble_BBSI = _dis("as inline0 target_offset",
                         lambda insn, _: _get_imm8_tok(insn.inline0(_)))
_disassemble_BEQ = _dis("as at target_offset")
_disassemble_BEQI = _dis("as b4const target_offset")
_disassemble_BEQZ = _dis("as target_offset")
_disassemble_BEQZ_N = _dis("as target_offset")
_disassemble_BF = _dis("bs target_offset")
_disassemble_BGE = _dis("as at target_offset")
_disassemble_BGEI = _dis("as b4const target_offset")
_disassemble_BGEU = _dis("as at target_offset")
_disassemble_BGEUI = _dis("as b4constu target_offset")
_disassemble_BGEZ = _dis("as target_offset")
_disassemble_BLT = _dis("as at target_offset")
_disassemble_BLTI = _dis("as b4const target_offset")
_disassemble_BLTU = _dis("as at target_offset")
_disassemble_BLTUI = _dis("as b4constu target_offset")
_disassemble_BLTZ = _dis("as target_offset")
_disassemble_BNALL = _dis("as at target_offset")
_disassemble_BNE = _dis("as at target_offset")
_disassemble_BNEI = _dis("as b4const target_offset")
_disassemble_BNEZ = _dis("as target_offset")
_disassemble_BNEZ_N = _dis("as target_offset")
_disassemble_BNONE = _dis("as at target_offset")

_disassemble_BREAK = _dis("s t")
_disassemble_BREAK_N = _dis("s")
_disassemble_BT = _dis("bs target_offset")

_disassemble_CALL0 = _dis("target_offset")

# Not bothering to disass register window stuff

_disassemble_CALLX0 = _dis("as")

_disassemble_CEIL_S = _dis("ar fs t")
# Skipping CLAMPS, I don't care about floats
# Skipping DHI, DHU, DHWB, DHWBI, DII, DIU, DIWB, DIWBI, DPFL, DPFR, DPFRO,
# DPFW, DPFWO, they deal with data caching, which is an extension
_disassemble_DSYNC = _dis("") # Just the mnem
# Skipping ENTRY, it deals with windowed registers
_disassemble_ESYNC = _dis("") # Just the mnem
_disassemble_EXCW = _dis("") # Just the mnem
_disassemble_EXTUI = _dis("ar at inline0 inline1",
                         lambda insn, _: _get_imm8_tok(insn.extui_shiftimm()),
                         lambda insn, _: _get_imm8_tok(insn.inline1(_)))
_disassemble_EXTW = _dis("")
# Skipping float stuff
_disassemble_IDTLB = _dis("as")
# Skipping IHI, IHU, III
_disassemble_IITLB = _dis("as")
# Skipping IIU
_disassemble_ILL = _dis("")
_disassemble_ILL_N = _dis("")
# Skipping IPF, IPFL
_disassemble_ISYNC = _dis("")
_disassemble_J = _dis("target_offset")
_disassemble_JX = _dis("as")
_disassemble_L8UI = _dis("at as imm8")
_disassemble_L16SI = _dis("at as inline0",
                          lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_L16UI = _dis("at as inline0",
                          lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_L32AI = _dis("at as inline0",
                          lambda insn, _: _get_imm32_tok(insn.inline0(_)))
# Skipping windowed L32E
_disassemble_L32I = _dis("at as inline0",
                          lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_L32I_N = _dis("at as inline0",
                          lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_L32R = _dis("at mem_offset")
# Skipping LDCT
# Skipping LDDEC,LDINC; they're MAC16
# Skipping LICT, LICW, instruction cache option
# Skipping LOOP, LOOPGTZ, LOOPNEZ, loop option
# Skipping LSI, LSIU, LSX, LSXU, MADD_S (floats)
_disassemble_MEMW = _dis("")
_disassemble_MOVI = _dis("at inline0",
                         lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_MOVI_N = _dis("as inline0",
                           lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_MOV_N = _dis("at as")
_disassemble_NEG = _dis("ar at")
_disassemble_NOP = _dis("")
_disassemble_NOP_N = _dis("")
_disassemble_NSA = _dis("at as")
_disassemble_NSAU = _dis("at as")
_disassemble_PDTLB = _dis("at as")
_disassemble_PITLB = _dis("at as")
_disassemble_RDTLB0 = _dis("at as")
_disassemble_RDTLB1 = _dis("at as")
_disassemble_RER = _dis("at as")
_disassemble_RET = _dis("") # Equivalent in function to "JX a0"
_disassemble_RET_N = _dis("") # Same function as RET
_disassemble_RFDD = _dis("")
_disassemble_RFDE = _dis("")
_disassemble_RFDO = _dis("")
_disassemble_RFE = _dis("")
_disassemble_RFI = _dis("s")
_disassemble_RITLB0 = _dis("at as")
_disassemble_RITLB1 = _dis("at as")
_disassemble_RSIL = _dis("at s")
_disassemble_RSYNC = _dis("")

_disassemble_S8I = _dis("at as imm8")
_disassemble_S16I = _dis("at as inline0",
                         lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_S32I = _dis("at as inline0",
                         lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_S32I_N = _dis("at as inline0",
                           lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_S32RI = _dis("at as inline0",
                         lambda insn, _: _get_imm32_tok(insn.inline0(_)))
_disassemble_SEXT = _dis("ar as inline0",
                         lambda insn, _: _get_imm8_tok(insn.t + 7))
_disassemble_SIMCALL = _dis("")
_disassemble_SLL = _dis("ar as")
_disassemble_SLLI = _dis("ar as inline0",
                          lambda insn, _: _get_imm8_tok(insn.inline0(_)))
_disassemble_SRA = _dis("ar at")
_disassemble_SRAI = _dis("ar at inline0",
                          lambda insn, _: _get_imm8_tok(insn.inline0(_)))
_disassemble_SRL = _dis("ar at")
_disassemble_SRLI = _dis("ar at s")
_disassemble_SSA8B = _dis("as")
_disassemble_SSA8L = _dis("as")
_disassemble_SSAI = _dis("inline0",
                         lambda insn, _: _get_imm8_tok(insn.inline0(_)))
_disassemble_SSL = _dis("as")
_disassemble_SSR = _dis("as")
_disassemble_SYSCALL = _dis("")
_disassemble_WAITI = _dis("s")
_disassemble_WDTLB = _dis("at as")
_disassemble_WER = _dis("at as")
_disassemble_WITLB = _dis("at as")
# _disassemble_WUR = _dis("at sr") # sr not yet handled
