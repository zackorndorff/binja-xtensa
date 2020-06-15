"""
Xtensa instruction decoder

This was created in roughly 10 hours over the course of a weekend with the
Xtensa manual in one window and Vim in the other. If you plan to make changes, I
suggest looking at section 7.3.1 "Opcode Maps" in the Xtensa manual, as the code
follows it directly (which explains the odd order of instructions). Overall, it
near-exactly matches the manual, with the exception of a few simplifications
involving instructions I didn't care about, and also fixing (<5) errors in the
manual.

The separation of concerns between instruction decoding, disassembly, and
lifting is roughly as follows: anything that can be done without knowing the
address is done as part of instruction decoding. There might be a couple places
where I declare the computation with a lambda in decoding, which is called
during disassembly with the address. Anyway, all the decoding are static
methods.

When I got to actual disassembly, I ran into a few issues where yes I had
decoded the instruction per the type "RRR", "RRI8", etc, but the immediate was
further encoded. In some cases (say, making a signed value from the imm8), I've
added methods to the Instruction class that will do that transformation. In more
instruction-specific cases, I added the ability to define a lambda inline that
does the specified transformation to the immediate (say it's stored shifted
right by a couple bits). In many cases, I've called it "inline0", then that is
referenced by the "inline0" in the disassembly code, as well as in the lifting
code.

Actual instruction decoding starts in Instruction.decode.

Link to the Xtensa docs/manual I was referencing:
    https://0x04.net/~mwk/doc/xtensa.pdf

"""
from enum import Enum


# https://stackoverflow.com/a/32031543
def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


class InstructionType(Enum):
    RRR = 1
    RSR = 2
    CALLX = 3
    RRI4 = 4
    RRI8 = 5
    RI16 = 6
    CALL = 7
    BRI8 = 8
    BRI12 = 9
    RRRN = 10
    RI7 = 11
    RI6 = 12


def mnem(_mnem, func, validity_predicate=None, **outer_kwargs):
    """Not public, just need the DSL to be prettier without _"""
    def inner(insn, *args, **kwargs):
        insn.mnem = _mnem
        getattr(Instruction, "_decode_fmt_" + func)(
            insn, *args, **kwargs
        )
        if validity_predicate and not validity_predicate(insn):
            insn.valid = False
        else:
            insn.valid = True
        if outer_kwargs:
            for key, value in outer_kwargs.items():
                if key.startswith("inline"):
                    bound = value.__get__(insn, insn.__class__)
                    setattr(insn, key, bound)
        return insn
    return inner


def _decode_components(insn, insn_bytes, components):
    for comp in components:
        setattr(insn, comp, globals()["decode_" + comp](insn_bytes))


# lambdas to decode the various control signals
decode_op0 = lambda insn_bytes: insn_bytes[0] & 0xf
decode_op1 = lambda insn_bytes: (insn_bytes[2]) & 0xf
decode_op2 = lambda insn_bytes: (insn_bytes[2] >> 4) & 0xf
decode_t = lambda insn_bytes: (insn_bytes[0] >> 4) & 0xf
decode_s = lambda insn_bytes: insn_bytes[1] & 0xf
decode_r = lambda insn_bytes: (insn_bytes[1] >> 4) & 0xf
decode_n = lambda insn_bytes: (insn_bytes[0] >> 4) & 3
decode_m = lambda insn_bytes: (insn_bytes[0] >> 6) & 3
decode_sr = lambda insn_bytes: insn_bytes[1]
decode_imm4 = lambda insn_bytes: (insn_bytes[2] >> 4) & 0xf
decode_imm8 = lambda insn_bytes: insn_bytes[2]
decode_imm12 = lambda insn_bytes: (insn_bytes[2] << 4) + ((insn_bytes[1] >> 4) & 0xf)
decode_imm16 = lambda insn_bytes: (insn_bytes[2] << 8) + insn_bytes[1]
decode_imm7 = lambda insn_bytes: (((insn_bytes[0] >> 4) & 0b111) << 4) + ((insn_bytes[1] >> 4) & 0xf)
decode_imm6 = lambda insn_bytes: (((insn_bytes[0] >> 4) & 0b11) << 4) + ((insn_bytes[1] >> 4) & 0xf)
decode_offset = lambda insn_bytes: (
    (insn_bytes[2] << 10) +
    (insn_bytes[1] << 2) +
    ((insn_bytes[0] >> 6) & 0b11)
)
decode_i = lambda insn_bytes: (insn_bytes[0] >> 7) & 1
decode_z = lambda insn_bytes: (insn_bytes[0] >> 6) & 1


class Instruction:

    # Instruction class starts with a bunch of utility methods. For the actual
    # decoding, see the "decode" classmethod.
    def __init__(self):
        self.op0 = None
        self.op1 = None
        self.op2 = None
        self.r = None
        self.s = None
        self.sr = None
        self.t = None
        self.n = None
        self.m = None
        self.i = None
        self.z = None
        self.imm6 = None
        self.imm7 = None
        self.imm8 = None
        self.imm12 = None
        self.imm16 = None
        self.offset = None
        self.length = None
        self.valid = None
        self.instruction_type = None

    # These are simple transformations done to immediate values and such.
    # Usually based on a line in the docs that say "the assembler will do such
    # and such to the immediate"
    def extui_shiftimm(self):
        if self.mnem != "EXTUI":
            return None
        return ((self.op1 & 1) << 4) + self.s

    def simm6(self):
        if self.imm6 is None:
            return None
        return sign_extend(self.imm6, 8)

    def simm8(self):
        if self.imm8 is None:
            return None
        return sign_extend(self.imm8, 8)

    def simm12(self):
        if self.imm12 is None:
            return None
        return sign_extend(self.imm12, 12)

    # For PC-relative instructions, we need the address to compute the
    # "target_offset". In non-branching cases, I've tried to instead call it a
    # "mem_offset" (although I suspect I missed a couple).
    def offset_imm6(self, addr):
        return addr + 4 + self.imm6

    def offset_simm6(self, addr):
        return addr + 4 + self.simm6()

    def offset_simm8(self, addr):
        return addr + 4 + self.simm8()

    def offset_simm12(self, addr):
        return addr + 4 + self.simm12()

    def offset_call0(self, addr):
        return (addr & 0xfffffffc) + (sign_extend(self.offset, 18) << 2) + 4

    def offset_j(self, addr):
        return addr + 4 + sign_extend(self.offset, 18)

    _target_offset_map = {
        "BALL": "offset_simm8",
        "BANY": "offset_simm8",
        "BBC": "offset_simm8",
        "BBCI": "offset_simm8",
        "BBS": "offset_simm8",
        "BBSI": "offset_simm8",
        "BEQ": "offset_simm8",
        "BEQI": "offset_simm8",
        "BEQZ": "offset_simm12",
        "BEQZ_N": "offset_imm6",
        "BF": "offset_simm8",
        "BGE": "offset_simm8",
        "BGEI": "offset_simm8",
        "BGEU": "offset_simm8",
        "BGEUI": "offset_simm8",
        "BGEZ": "offset_simm12",
        "BLT": "offset_simm8",
        "BLTI": "offset_simm8",
        "BLTU": "offset_simm8",
        "BLTUI": "offset_simm8",
        "BLTZ": "offset_simm12",
        "BNALL": "offset_simm8",
        "BNE": "offset_simm8",
        "BNEI": "offset_simm8",
        "BNEZ": "offset_simm12",
        "BNEZ_N": "offset_imm6",
        "BNONE": "offset_simm8",
        "BT": "offset_simm8",
        "CALL0": "offset_call0",
        "J": "offset_j",
    }
    def target_offset(self, addr):
        try:
            mapped = self._target_offset_map[self.mnem.replace(".", "_")]
        except KeyError:
            return None
        func = getattr(self, mapped, None)
        if not func:
            raise Exception(f"Invalid handler for insn {self.mnem} in _target_offset_map")
        return func(addr)

    def offset_l32r(self, addr):
        enc = sign_extend(self.imm16 | 0xFFFF0000, 32) << 2
        return (enc + addr + 3) & 0xFFFFFFFC

    # mem_offset is roughly the same as target_offset, but for data accesses and
    # not jumps
    _mem_offset_map = {
        "L32R": "offset_l32r",
    }
    def mem_offset(self, addr):
        try:
            mapped = self._mem_offset_map[self.mnem.replace(".", "_")]
        except KeyError:
            return None
        func = getattr(self, mapped, None)
        if not func:
            raise Exception(f"Invalid handler for insn {self.mnem} in _mem_offset_map")
        return func(addr)

    # In a few places, an immediate is an index into these lookup tables. The
    # RTN in the docs calls it "B4CONST", so I do too.
    _b4const_vals = [
        -1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256,
    ]
    _b4constu_vals = [
        32768, 65536, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256,
    ]
    _b4const_map = {
        "BEQI": "r",
        "BGEI": "r",
        "BLTI": "r",
        "BNEI": "r",
    }
    _b4constu_map = {
        "BGEUI": "r",
        "BLTUI": "r",
    }
    def b4const(self):
        try:
            comp = self._b4const_map[self.mnem]
        except KeyError:
            raise

        enc = getattr(self, comp)
        return self._b4const_vals[enc]

    def b4constu(self):
        try:
            comp = self._b4constu_map[self.mnem]
        except KeyError:
            raise

        enc = getattr(self, comp)
        return self._b4constu_vals[enc]

    # Table 5-128 Numerical List of Special Registers
    # This allows us to render "RSR.REGNAME" versus RSR at, <thing>
    _special_reg_map = {
        0: "LBEG",
        1: "LEND",
        2: "LCOUNT",
        3: "SAR",
        4: "BR",
        5: "LITBASE",
        12: "SCOMPARE1",
        16: "ACCLO",
        17: "ACCHI",
        32: "M0",
        33: "M1",
        34: "M2",
        35: "M3",
        72: "WindowBase",
        73: "WindowStart",
        83: "PTEVADDR",
        89: "MMID",
        90: "RASID",
        91: "ITLBCFG",
        92: "DTLBCFG",
        96: "IBREAKENABLE",
        98: "CACHEATTR",
        99: "ATOMCTL",
        104: "DDR",
        106: "MEPC",
        107: "MEPS",
        108: "MESAVE",
        109: "MESR",
        110: "MECR",
        111: "MEVADDR",
        128: "IBREAKA0",
        129: "IBREAKA1",
        144: "DBREAKA0",
        145: "DBREAKA1",
        160: "DBREAKC0",
        161: "DBREAKC1",
        177: "EPC1",
        178: "EPC2",
        179: "EPC3",
        180: "EPC4",
        181: "EPC5",
        182: "EPC6",
        183: "EPC7",
        192: "DEPC",
        194: "EPS2",
        195: "EPS3",
        196: "EPS4",
        197: "EPS5",
        198: "EPS6",
        199: "EPS7",
        209: "EXCSAVE1",
        210: "EXCSAVE2",
        211: "EXCSAVE3",
        212: "EXCSAVE4",
        213: "EXCSAVE5",
        214: "EXCSAVE6",
        215: "EXCSAVE7",
        224: "CPENABLE",
        226: "INTERRUPT", # Also known as INTSET
        227: "INTCLEAR",
        228: "INTENABLE",
        230: "PS",
        231: "VECBASE",
        232: "EXCCAUSE",
        233: "DEBUGCAUSE",
        234: "CCOUNT",
        235: "PRID",
        236: "ICOUNT",
        237: "ICOUNTLEVEL",
        238: "EXCVADDR",
        240: "CCOMPARE0",
        241: "CCOMPARE1",
        242: "CCOMPARE2",
        244: "MISC0",
        245: "MISC1",
        246: "MISC2",
        247: "MISC3",
    }

    def get_sr_name(self):
        if self.mnem not in ["RSR", "WSR", "XSR"]:
            return None
        try:
            return self._special_reg_map[self.sr]
        except KeyError:
            return str(self.sr)

    # For instruction decoding, we follow the tables in xtensa.pdf
    # (7.3.1 Opcode Maps)
    # We begin with Table 7-192 Whole Opcode Space. This switches off op0 to
    # subtables, which we then filter through to sub-sub-tables, etc. 10 hours
    # later, we made it to the bottom :)
    _op0_map = [
        "QRST", "L32R", "LSAI", "LSCI",
        "MAC16", "CALLN", "SI", "B",
        "L32I_N", "S32I_N", "ADD_N", "ADDI_N",
        "ST2", "ST3", None, None, # None is reserved
    ]
    @classmethod
    def decode(cls, insn_bytes):
        insn = Instruction()
        return cls._do_tbl_layer(insn, insn_bytes, "op0", cls._op0_map)

    # At each "layer" of the tables, we look up some control signal. In this
    # case, it was op0. op0 has 4 bits for a 16 entry table. We can do one of
    # two things: a sub-table or a leaf (instruction). By the magic of Python
    # metaprogramming, we lookup the classmethod _decode_<item>, which we
    # implement either as a function for a table layer, or we use the mnem
    # helper to indicate it's a leaf function.

    # These are the actual instructions found in the first table. Arguments to
    # mnem are mnemonic, instruction type, an optional predicate specifying if
    # the encoding is valid (for when the manual says t must be 0 or something),
    # and then "inline" kwargs that end up defining methods for disassembly and
    # lifting to use.
    _decode_L32R = mnem("L32R", "RI16") # op0, t, imm16
    _decode_L32I_N = mnem("L32I.N", "RRRN",
                          inline0=lambda insn, _: insn.r << 2)
    _decode_S32I_N = mnem("S32I.N", "RRRN",
                          inline0=lambda insn, _: insn.r << 2)
    _decode_ADD_N = mnem("ADD.N", "RRRN")
    _decode_ADDI_N = mnem("ADDI.N", "RRRN",
                          inline0=lambda insn, _: insn.t if insn.t != 0 else -1)


    # The next three functions implement the metaprogramming glue between layers
    @classmethod
    def _do_tbl_layer(cls, insn, insn_bytes, component, map):
        """Do the lookups for one table layer.
        
        component is the string to decode, like "op1", or "r".
        map is the map to look up in
        """
        return cls._do_lut(insn, insn_bytes,
                    [(component, globals()["decode_" + component])],
                    component,
                    map)

    @classmethod
    def _do_lut(cls,
               insn,
               insn_bytes,
               lookup_map,
               value_to_look_up,
               table_to_look_in,
               ):
        """Do an iteration of table-lookups

        Tensilica has a bunch of tables that define the instruction encoding.
        We decode them a layer at a time, dispatching to relevant handlers at
        each level. By the time we're done, we should have the whole instruction
        decoded.

        At each layer, we read one or more values out of the insn bytes and
        assign it to the decoded properties. We then grab a value from the table
        using one of those values and call the next layer

        Params:
            insn (Instruction): the instruction object to fill in
            insn_bytes (bytes): the instruction bytes we're decoding

            lookup_map (List[Tuple]): list of tuples of
            (decoded_name, function_to_decode). The function will receive
            insn_bytes as a param and should return a numeric value.

            value_to_look_up (string): One of the decoded_name values from the
            previous param

            table_to_look_in (List): The table to look in (access as cls._name
            and pass that in)

        """
        for (decoded_name, function_to_decode) in lookup_map:
            try:
                getattr(insn, decoded_name)
            except AttributeError:
                raise
            setattr(insn, decoded_name, function_to_decode(insn_bytes))

        value = getattr(insn, value_to_look_up)
        return cls._call_from_map(table_to_look_in, value, insn, insn_bytes)

    @staticmethod
    def _call_from_map(map, index, insn, insn_bytes):
        """Part of the operation of _do_lut, see there for comments"""
        try:
            name = "_decode_" + map[index]
        except IndexError:
            raise Exception(f"Unsupported index {index} in map {map}")

        func = getattr(Instruction, name, None)
        if not func:
            raise Exception(f"Unimplemented: {name}")

        return func(insn, insn_bytes)

    # From here down, it's a pretty mechanical translation of the Xtensa docs

    _qrst_map = [
        "RST0", "RST1", "RST2", "RST3",
        "EXTUI", "EXTUI", "CUST0", "CUST1",
        "LSCX", "LSC4", "FP0", "FP1",
        None, None, None, None,
    ]
    @classmethod
    def _decode_QRST(cls, insn, insn_bytes):
        # Formats RRR, CALLX, RSR (t, s, r, op2 vary)
        # That means op1 is the commonality we'll map off of
        return cls._do_tbl_layer(insn, insn_bytes, "op1", cls._qrst_map)

    _decode_EXTUI = mnem("EXTUI",
                         "RRR", # RRR is dubious for this... it's complex
                         # IIRC inline0 ended up being named something else but
                         # I didn't want to reuse the number
                         inline1=lambda insn, _: insn.op2 + 1
                         )

    _rst0_map = [
        "ST0", "AND", "OR", "XOR",
        "ST1", "TLB", "RT0", None, # None is reserved
        "ADD", "ADDX2", "ADDX4", "ADDX8",
        "SUB", "SUBX2", "SUBX4", "SUBX8",
    ]
    @classmethod
    def _decode_RST0(cls, insn, insn_bytes):
        # Formats RRR and CALLX (t, s, r vary)
        # That means op2 is the commonality we'll map off of
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._rst0_map)

    _decode_AND = mnem("AND", "RRR")
    _decode_OR = mnem("OR", "RRR")
    _decode_XOR = mnem("XOR", "RRR")
    _decode_ADD = mnem("ADD", "RRR")
    _decode_ADDX2 = mnem("ADDX2", "RRR")
    _decode_ADDX4 = mnem("ADDX4", "RRR")
    _decode_ADDX8 = mnem("ADDX8", "RRR")
    _decode_SUB = mnem("SUB", "RRR")
    _decode_SUBX2 = mnem("SUBX2", "RRR")
    _decode_SUBX4 = mnem("SUBX4", "RRR")
    _decode_SUBX8 = mnem("SUBX8", "RRR")

    _st0_map = [
        "SNM0", "MOVSP", "SYNC", "RFEI",
        "BREAK", "SYSCALL", "RSIL", "WAITI",
        "ANY4", "ALL4", "ANY8", "ALL8",
        None, None, None, None, # these are reserved
    ]
    @classmethod
    def _decode_ST0(cls, insn, insn_bytes):
        # Formats RRR and CALLX
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._st0_map)

    _decode_MOVSP = mnem("MOVSP", "RRR")
    _decode_BREAK = mnem("BREAK", "RRR")
    _decode_SYSCALL = mnem("SYSCALL", "RRR", lambda insn: insn.s == 0 and insn.t == 0)
    _decode_RSIL = mnem("RSIL", "RRR")
    _decode_WAITI = mnem("WAITI", "RRR", lambda insn: insn.t == 0)
    _decode_ANY4 = mnem("ANY4", "RRR")
    _decode_ALL4 = mnem("ALL4", "RRR")
    _decode_ANY8 = mnem("ANY8", "RRR")
    _decode_ALL8 = mnem("ALL8", "RRR")

    _snm0_map = [
        "ILL", None, "JR", "CALLX", # None is reserved
    ]
    @classmethod
    def _decode_SNM0(cls, insn, insn_bytes):
        # Format CALLX (n, s vary)
        return cls._do_tbl_layer(insn, insn_bytes, "m", cls._snm0_map)

    _decode_ILL = mnem("ILL", "CALLX", lambda insn: insn.s == 0 and insn.n == 0)

    _jr_map = [
        "RET", "RETW", "JX", None, # None is reserved
    ]
    @classmethod
    def _decode_JR(cls, insn, insn_bytes):
        # Format CALLX (s varies)
        return cls._do_tbl_layer(insn, insn_bytes, "n", cls._jr_map)

    _decode_RET = mnem("RET", "CALLX", lambda insn: insn.s == 0)
    _decode_RETW = mnem("RETW", "CALLX", lambda insn: insn.s == 0)
    _decode_JX = mnem("JX", "CALLX")

    _callx_map = [
        "CALLX0", "CALLX4", "CALLX8", "CALLX12",
    ]
    @classmethod
    def _decode_CALLX(cls, insn, insn_bytes):
        # Format CALLX (s varies)
        return cls._do_tbl_layer(insn, insn_bytes, "n", cls._callx_map)

    _decode_CALLX0 = mnem("CALLX0", "CALLX")
    _decode_CALLX4 = mnem("CALLX4", "CALLX")
    _decode_CALLX8 = mnem("CALLX8", "CALLX")
    _decode_CALLX12 = mnem("CALLX12", "CALLX")

    # SYNC
    _sync_map = [
        "ISYNC", "RSYNC", "ESYNC", "DSYNC",
        None, None, None, None, # None is reserved
        "EXCW", None, None, None,
        "MEMW", "EXTW", None, None,
    ]
    @classmethod
    def _decode_SYNC(cls, insn, insn_bytes):
        # Format RRR (s varies)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._sync_map)

    _decode_ISYNC = mnem("ISYNC", "RRR", lambda insn: insn.s == 0)
    _decode_RSYNC = mnem("RSYNC", "RRR", lambda insn: insn.s == 0)
    _decode_ESYNC = mnem("ESYNC", "RRR", lambda insn: insn.s == 0)
    _decode_DSYNC = mnem("DSYNC", "RRR", lambda insn: insn.s == 0)
    _decode_EXCW = mnem("EXCW", "RRR", lambda insn: insn.s == 0)
    _decode_MEMW = mnem("MEMW", "RRR", lambda insn: insn.s == 0)
    _decode_EXTW = mnem("EXTW", "RRR", lambda insn: insn.s == 0)

    _rfei_map = [
        "RFET", "RFI", "RFME", None, # None is reserved
        None, None, None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_RFEI(cls, insn, insn_bytes):
        # Format RRR (s varies)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._rfei_map)

    _decode_RFI = mnem("RFI", "RRR")
    _decode_RFME = mnem("RFME", "RRR", lambda insn: insn.s == 0)

    _rfet_map = [
        "RFE", "RFUI", "RFDE", None, # None is reserved
        "RFWO", "RFWU", None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_RFET(cls, insn, insn_bytes):
        # Format RRR (no bits vary)
        return cls._do_tbl_layer(insn, insn_bytes, "s", cls._rfet_map)

    _decode_RFE = mnem("RFE", "RRR")
    _decode_RFUI = mnem("RFUI", "RRR")
    _decode_RFDE = mnem("RFDE", "RRR")
    _decode_RFWO = mnem("RFWO", "RRR")
    _decode_RFWU = mnem("RFWU", "RRR")

    _st1_map = [
        "SSR", "SSL", "SSA8L", "SSA8B",
        "SSAI", None, "RER", "WER", # None is reserved
        "ROTW", None, None, None, # None is reserved
        None, None, "NSA", "NSAU",
    ]
    @classmethod
    def _decode_ST1(cls, insn, insn_bytes):
        # Format RRR (t, s vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._st1_map)

    _decode_SSR = mnem("SSR", "RRR", lambda insn: insn.t == 0)
    _decode_SSL = mnem("SSL", "RRR", lambda insn: insn.t == 0)
    _decode_SSA8L = mnem("SSA8L", "RRR", lambda insn: insn.t == 0)
    _decode_SSA8B = mnem("SSA8B", "RRR", lambda insn: insn.t == 0)
    _decode_SSAI = mnem("SSAI", "RRR", lambda insn: insn.t == 0,
                        inline0=lambda insn, _: insn.s + ((insn.t & 1) << 4) )
    _decode_RER = mnem("RER", "RRR")
    _decode_WER = mnem("WER", "RRR")
    _decode_ROTW = mnem("ROTW", "RRR", lambda insn: insn.s == 0)
    _decode_NSA = mnem("NSA", "RRR")
    _decode_NSAU = mnem("NSAU", "RRR")

    _tlb_map = [
        None, None, None, "RITLB0", # None is reserved
        "IITLB", "PITLB", "WITLB", "RITLB1",
        None, None, None, "RDTLB0",
        "IDTLB", "PDTLB", "WDTLB", "RDTLB1",
    ]
    @classmethod
    def _decode_TLB(cls, insn, insn_bytes):
        # Format RRR (t, s vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._tlb_map)

    _decode_RITLB0 = mnem("RITLB0", "RRR")
    _decode_IITLB = mnem("IITLB", "RRR", lambda insn: insn.t == 0)
    _decode_PITLB = mnem("PITLB", "RRR")
    _decode_WITLB = mnem("WITLB", "RRR")
    _decode_RITLB1 = mnem("RITLB1", "RRR")
    _decode_RDTLB0 = mnem("RDTLB0", "RRR")
    _decode_IDTLB = mnem("IDTLB", "RRR", lambda insn: insn.t == 0)
    _decode_PDTLB = mnem("PDTLB", "RRR")
    _decode_WDTLB = mnem("WDTLB", "RRR")
    _decode_RDTLB1 = mnem("RDTLB1", "RRR")

    _rt0_map = [
        "NEG", "ABS", None, None,
        None, None, None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_RT0(cls, insn, insn_bytes):
        # Format RRR (t, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "s", cls._rt0_map)

    _decode_NEG = mnem("NEG", "RRR")
    _decode_ABS = mnem("ABS", "RRR")

    _rst1_map = [
        "SLLI", "SLLI", "SRAI", "SRAI",
        "SRLI", None, "XSR", "ACCER",
        "SRC", "SRL", "SLL", "SRA",
        "MUL16U", "MUL16S", None, "IMP"
    ]
    @classmethod
    def _decode_RST1(cls, insn, insn_bytes):
        # Format RRR (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._rst1_map)

    _decode_SLLI = mnem("SLLI", "RRR",
                        inline0=lambda insn, _: 32 - ( insn.t + ((insn.op2 & 1) << 4) ))
    _decode_SRAI = mnem("SRAI", "RRR",
                        inline0=lambda insn, _: insn.s + ((insn.op2 & 1) << 4))
    _decode_SRLI = mnem("SRLI", "RRR")
    _decode_XSR = mnem("XSR", "RSR")
    _decode_SRC = mnem("SRC", "RRR")
    _decode_SRL = mnem("SRL", "RRR", lambda insn: insn.s == 0)
    _decode_SLL = mnem("SLL", "RRR", lambda insn: insn.t == 0)
    _decode_SRA = mnem("SRA", "RRR", lambda insn: insn.s == 0)
    _decode_MUL16U = mnem("MUL16U", "RRR")
    _decode_MUL16S = mnem("MUL16S", "RRR")

    _accer_map = [
        None, None, None, None,
        None, None, "RER", "WER",
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_ACCER(cls, insn, insn_bytes):
        # Format RRR (t, s vary)
        # There's a bug in the manual here: it says to filter on op2, however we
        # filtered on op2 to get here. Inspection suggests that we should in
        # fact filter on the following values for r:
        # RER = 0110
        # WER = 0111
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._accer_map)

    _decode_RER = mnem("RER", "RRR")
    _decode_WER = mnem("WER", "RRR")

    _imp_map = [
        "LICT", "SICT", "LICW", "SICW",
        None, None, None, None, # None is reserved
        "LDCT", "SDCT", None,  None,
        None, None, "RFDX", None,
    ]
    @classmethod
    def _decode_IMP(cls, insn, insn_bytes):
        # Format RRR (t, s vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._imp_map)

    _decode_LICT = mnem("LICT", "RRR")
    _decode_SICT = mnem("SICT", "RRR")
    _decode_LICW = mnem("LICW", "RRR")
    _decode_SICW = mnem("SICW", "RRR")
    _decode_LDCT = mnem("LDCT", "RRR")
    _decode_SDCT = mnem("SDCT", "RRR")

    _rfdx_map = [
        "RFDO", "RFDD", None, None, # None is reserved
        None, None, None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_RFDX(cls, insn, insn_bytes):
        # Format RRR (s varies)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._rfdx_map)

    _decode_RFDO = mnem("RFDO", "RRR", lambda insn: insn.s == 0)
    _decode_RFDD = mnem("RFDD", "RRR", lambda insn: insn.s in [0, 1])

    _rst2_map = [
        "ANDB", "ANDBC", "ORB", "ORBC",
        "XORB", None, None, None,
        "MULL", None, "MULUH", "MULSH",
        "QUOU", "QUOS", "REMU", "REMS",
    ]
    @classmethod
    def _decode_RST2(cls, insn, insn_bytes):
        # Format RRR (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._rst2_map)

    _decode_ANDB = mnem("ANDB", "RRR")
    _decode_ANDBC = mnem("ANDBC", "RRR")
    _decode_ORB = mnem("ORB", "RRR")
    _decode_ORBC = mnem("ORBC", "RRR")
    _decode_XORB = mnem("XORB", "RRR")
    _decode_MULL = mnem("MULL", "RRR")
    _decode_MULUH = mnem("MULUH", "RRR")
    _decode_MULSH = mnem("MULSH", "RRR")
    _decode_QUOU = mnem("QUOU", "RRR")
    _decode_QUOS = mnem("QUOS", "RRR")
    _decode_REMU = mnem("REMU", "RRR")
    _decode_REMS = mnem("REMS", "RRR")

    _rst3_map = [
        "RSR", "WSR",  "SEXT", "CLAMPS",
        "MIN", "MAX", "MINU", "MAXU",
        "MOVEQZ", "MOVNEZ", "MOVLTZ", "MOVGEZ",
        "MOVF", "MOVT", "RUR", "WUR",
    ]
    @classmethod
    def _decode_RST3(cls, insn, insn_bytes):
        # Formats RRR and RSR (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._rst3_map)

    _decode_RSR = mnem("RSR", "RSR")
    _decode_WSR = mnem("WSR", "RSR")
    _decode_SEXT = mnem("SEXT", "RRR")
    _decode_CLAMPS = mnem("CLAMPS", "RRR")
    _decode_MIN = mnem("MIN", "RRR")
    _decode_MAX = mnem("MAX", "RRR")
    _decode_MINU = mnem("MINU", "RRR")
    _decode_MAXU = mnem("MAXU", "RRR")
    _decode_MOVEQZ = mnem("MOVEQZ", "RRR")
    _decode_MOVNEZ = mnem("MOVNEZ", "RRR")
    _decode_MOVLTZ = mnem("MOVLTZ", "RRR")
    _decode_MOVGEZ = mnem("MOVGEZ", "RRR")
    _decode_MOVF = mnem("MOVF", "RRR")
    _decode_MOVT = mnem("MOVT", "RRR")
    _decode_RUR = mnem("RUR", "RRR") # lol, could probably treat as RSR
    _decode_WUR = mnem("WUR", "RSR")

    _lscx_map = [
        "LSX", "LSXU", None, None, # None is reserved
        "SSX", "SSXU", None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_LSCX(cls, insn, insn_bytes):
        # Format RRR (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._lscx_map)

    _decode_LSX = mnem("LSX", "RRR")
    _decode_LSXU = mnem("LSXU", "RRR")
    _decode_SSX = mnem("SSX", "RRR")
    _decode_SSXU = mnem("SSXU", "RRR")

    _lsc4_map = [
        "L32E", None, None, None,
        "S32E", None, None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_LSC4(cls, insn, insn_bytes):
        # Format RRI4 (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._lsc4_map)

    _decode_L32E = mnem("L32E", "RRI4")
    _decode_S32E = mnem("S32E", "RRI4")

    _fp0_map = [
        "ADD_S", "SUB_S", "MUL_S", None, # None is reserved
        "MADD_S", "MSUB_S", None, None,
        "ROUND_S", "TRUNC_S", "FLOOR_S", "CEIL_S",
        "FLOAT_S", "UFLOAT_S", "UTRUNC_S", "FP1OP",
    ]
    @classmethod
    def _decode_FP0(cls, insn, insn_bytes):
        # Format RRR (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._fp0_map)

    _decode_ADD_S = mnem("ADD_S", "RRR")
    _decode_SUB_S = mnem("SUB_S", "RRR")
    _decode_MUL_S = mnem("MUL_S", "RRR")
    _decode_MADD_S = mnem("MADD_S", "RRR")
    _decode_MSUB_S = mnem("MSUB_S", "RRR")
    _decode_ROUND_S = mnem("ROUND_S", "RRR")
    _decode_TRUNC_S = mnem("TRUNC_S", "RRR")
    _decode_FLOOR_S = mnem("FLOOR_S", "RRR")
    _decode_CEIL_S = mnem("CEIL_S", "RRR")
    _decode_FLOAT_S = mnem("FLOAT_S", "RRR")
    _decode_UFLOAT_S = mnem("UFLOAT_S", "RRR")
    _decode_UTRUNC_S = mnem("UTRUNC_S", "RRR")

    _fp1op_map = [
        "MOV_S", "ABS_S", None, None, # None is reserved
        "RFR", "WFR", "NEG_S", None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_FP1OP(cls, insn, insn_bytes):
        # Format RRR (s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._fl1op_map)

    _decode_MOV_S = mnem("MOV_S", "RRR")
    _decode_ABS_S = mnem("ABS_S", "RRR")
    _decode_RFR = mnem("RFR", "RRR")
    _decode_WFR = mnem("WFR", "RRR")
    _decode_NEG_S = mnem("NEG_S", "RRR")

    _fp1_map = [
        None, "UN_S", "OEQ_S", "UEQ_S", # None is reserved
        "OLT_S", "ULT_S", "OLE_S", "ULE_S",
        "MOVEQZ_S", "MOVNEZ_S", "MOVLTZ_S", "MOVGEZ_S",
        "MOVF_S", "MOVT_S", None, None,
    ]
    @classmethod
    def _decode_FP1(cls, insn, insn_bytes):
        # Format RRR (t, s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._fp1_map)

    _decode_UN_S = mnem("UN.S", "RRR")
    _decode_OEQ_S = mnem("OEQ.S", "RRR")
    _decode_UEQ_S = mnem("UEQ.S", "RRR")
    _decode_OLT_S = mnem("OLT.S", "RRR")
    _decode_ULT_S = mnem("ULT.S", "RRR")
    _decode_OLE_S = mnem("OLE.S", "RRR")
    _decode_ULE_S = mnem("ULE.S", "RRR")
    _decode_MOVEQZ_S = mnem("MOVEQZ.S", "RRR")
    _decode_MOVNEZ_S = mnem("MOVNEZ.S", "RRR")
    _decode_MOVLTZ_S = mnem("MOVLTZ.S", "RRR")
    _decode_MOVGEZ_S = mnem("MOVGEZ.S", "RRR")
    _decode_MOVF_S = mnem("MOVF.S", "RRR")
    _decode_MOVT_S = mnem("MOVT.S", "RRR")

    _lsai_map = [
        "L8UI", "L16UI", "L32I", None, # None is reserved
        "S8I", "S16I", "S32I", "CACHE",
        None, "L16SI", "MOVI", "L32AI",
        "ADDI", "ADDMI", "S32C1I", "S32RI",
    ]
    @classmethod
    def _decode_LSAI(cls, insn, insn_bytes):
        # Formats RRI8 and RRI4 (t, s, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._lsai_map)

    _decode_L8UI = mnem("L8UI", "RRI8")
    _decode_L16UI = mnem("L16UI", "RRI8",
                         inline0=lambda insn, _: insn.imm8 << 1)
    _decode_L32I = mnem("L32I", "RRI8",
                        inline0=lambda insn, _: insn.imm8 << 2)
    _decode_S8I = mnem("S8I", "RRI8")
    _decode_S16I = mnem("S16I", "RRI8",
                        inline0=lambda insn, _: insn.imm8 << 1)
    _decode_S32I = mnem("S32I", "RRI8",
                        inline0=lambda insn, _: insn.imm8 << 2)
    _decode_L16SI = mnem("L16SI", "RRI8",
                         inline0=lambda insn, _: insn.imm8 << 1)
    _decode_MOVI = mnem("MOVI", "RRI8",
                        inline0=lambda insn, _:
                            sign_extend((insn.s << 8) + insn.imm8, 12)
                        )
    _decode_L32AI = mnem("L32AI", "RRI8",
                         inline0=lambda insn, _: insn.imm8 << 2)
    _decode_ADDI = mnem("ADDI", "RRI8")
    _decode_ADDMI = mnem("ADDMI", "RRI8")
    _decode_S32C1I = mnem("S32C1I", "RRI8")
    _decode_S32RI = mnem("S32RI", "RRI8",
                         inline0=lambda insn, _: insn.imm8 << 2)

    _cache_map = [
        "DPFR", "DPFW", "DPFRO", "DPFWO",
        "DHWB", "DHWBI", "DHI", "DII",
        "DCE", None, None, None, # None is reserved
        "IPF", "ICE", "IHI", "III",
    ]
    @classmethod
    def _decode_CACHE(cls, insn, insn_bytes):
        # Formats RRI8 and RRI4 (s, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._cache_map)

    _decode_DPFR = mnem("DPFR", "RRI8")
    _decode_DPFW = mnem("DPFW", "RRI8")
    _decode_DPFRO = mnem("DPFRO", "RRI8")
    _decode_DPFWO = mnem("DPFWO", "RRI8")
    _decode_DHWB = mnem("DHWB", "RRI8")
    _decode_DHWBI = mnem("DHWBI", "RRI8")
    _decode_DHI = mnem("DHI", "RRI8")
    _decode_DII = mnem("DII", "RRI8")
    _decode_IPF = mnem("IPF", "RRI8")
    _decode_IHI = mnem("IHI", "RRI8")
    _decode_III = mnem("III", "RRI8")

    _dce_map = [
        "DPFL", None, "DHU", "DIU", # None is reserved
        "DIWB", "DIWBI", None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_DCE(cls, insn, insn_bytes):
        # Format RRI4 (s, imm4 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op1", cls._dce_map)

    _decode_DPFL = mnem("DPFL", "RRI4")
    _decode_DHU = mnem("DHU", "RRI4")
    _decode_DIU = mnem("DIU", "RRI4")
    _decode_DIWB = mnem("DIWB", "RRI4")
    _decode_DIWBI = mnem("DIWBI", "RRI4")

    _ice_map = [
        "IPFL", None, "IHU", "IIU", # None is reserved
        None, None, None, None,
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_ICE(cls, insn, insn_bytes):
        # Format RRI4 (s, imm4 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op1", cls._ice_map)

    _decode_IPFL = mnem("IPFL", "RRI4")
    _decode_IHU = mnem("IHU", "RRI4")
    _decode_IIU = mnem("IIU", "RRI4")

    _lsci_map = [
        "LSI", None, None, None, # None is reserved
        "SSI", None, None, None,
        "LSIU", None, None, None,
        "SSIU", None, None, None,
    ]
    @classmethod
    def _decode_LSCI(cls, insn, insn_bytes):
        # format RRI8 (t, s, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._lsci_map)

    _decode_LSI = mnem("LSI", "RRI8")
    _decode_SSI = mnem("SSI", "RRI8")
    _decode_LSIU = mnem("LSIU", "RRI8")
    _decode_SSIU = mnem("SSIU", "RRI8")

    _mac16_map = [
        "MACID", "MACCD", "MACDD", "MACAD",
        "MACIA", "MACCA", "MACDA", "MACAA",
        "MACI", "MACC", None, None, # None is reserved
        None, None, None, None,
    ]
    @classmethod
    def _decode_MAC16(cls, insn, insn_bytes):
        # format RRR (t, s, r, op1 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "op2", cls._mac16_map)

    # TODO: Skipping this MAC stuff, seems like a vector processor, that I doubt
    # the ESP8266 has... 

    _calln_map = [
        "CALL0", "CALL4", "CALL8", "CALL12",
    ]
    @classmethod
    def _decode_CALLN(cls, insn, insn_bytes):
        # Format CALL (offset varies)
        return cls._do_tbl_layer(insn, insn_bytes, "n", cls._calln_map)

    _decode_CALL0 = mnem("CALL0", "CALL")
    _decode_CALL4 = mnem("CALL4", "CALL")
    _decode_CALL8 = mnem("CALL8", "CALL")
    _decode_CALL12 = mnem("CALL12", "CALL")

    _si_map = [
        "J", "BZ", "BI0", "BI1",
    ]
    @classmethod
    def _decode_SI(cls, insn, insn_bytes):
        # Formats CALL, BRI8 and BRI12 (offset varies)
        return cls._do_tbl_layer(insn, insn_bytes, "n", cls._si_map)

    _decode_J = mnem("J", "CALL")

    _bz_map = [
        "BEQZ", "BNEZ", "BLTZ", "BGEZ",
    ]
    @classmethod
    def _decode_BZ(cls, insn, insn_bytes):
        # Format BRI12 (s, imm12 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "m", cls._bz_map)

    _decode_BEQZ = mnem("BEQZ", "BRI12")
    _decode_BNEZ = mnem("BNEZ", "BRI12")
    _decode_BLTZ = mnem("BLTZ", "BRI12")
    _decode_BGEZ = mnem("BGEZ", "BRI12")

    _bi0_map = [
        "BEQI", "BNEI", "BLTI", "BGEI",
    ]
    @classmethod
    def _decode_BI0(cls, insn, insn_bytes):
        # Format BRI8 (s, r, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "m", cls._bi0_map)

    _decode_BEQI = mnem("BEQI", "BRI8")
    _decode_BNEI = mnem("BNEI", "BRI8")
    _decode_BLTI = mnem("BLTI", "BRI8")
    _decode_BGEI = mnem("BGEI", "BRI8")

    _bi1_map = [
        "ENTRY",
        "B1",
        "BLTUI",
        "BGEUI",
    ]
    @classmethod
    def _decode_BI1(cls, insn, insn_bytes):
        # Formats BRI8 and BRI12 (s, r, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "m", cls._bi1_map)

    _decode_ENTRY = mnem("ENTRY", "BRI12")
    _decode_BLTUI = mnem("BLTUI", "BRI8")
    _decode_BGEUI = mnem("BGEUI", "BRI8")

    _b1_map = [
        "BF", "BT", None, None, # None is reserved
        None, None, None, None,
        "LOOP", "LOOPNEZ", "LOOPGTZ", None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_B1(cls, insn, insn_bytes):
        # Format BRI8 (s, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._b1_map)

    _decode_BF = mnem("BF", "BRI8")
    _decode_BT = mnem("BT", "BRI8")
    _decode_LOOP = mnem("LOOP", "BRI8")
    _decode_LOOPNEZ = mnem("LOOPNEZ", "BRI8")
    _decode_LOOPGTZ = mnem("LOOPGTZ", "BRI8")

    _b_map = [
        "BNONE", "BEQ", "BLT", "BLTU",
        "BALL", "BBC", "BBCI", "BBCI",
        "BANY", "BNE", "BGE", "BGEU",
        "BNALL", "BBS", "BBSI", "BBSI"
    ]
    @classmethod
    def _decode_B(cls, insn, insn_bytes):
        # Format RRI8 (t, s, imm8 vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._b_map)

    _decode_BNONE = mnem("BNONE", "RRI8")
    _decode_BEQ = mnem("BEQ", "RRI8")
    _decode_BLT = mnem("BLT", "RRI8")
    _decode_BLTU = mnem("BLTU", "RRI8")
    _decode_BALL = mnem("BALL", "RRI8")
    _decode_BBC = mnem("BBC", "RRI8")
    _decode_BBCI = mnem("BBCI", "RRI8",
                        inline0=lambda insn, _: insn.t + ((insn.r & 1) << 4))
    _decode_BANY = mnem("BANY", "RRI8")
    _decode_BNE = mnem("BNE", "RRI8")
    _decode_BGE = mnem("BGE", "RRI8")
    _decode_BGEU = mnem("BGEU", "RRI8")
    _decode_BNALL = mnem("BNALL", "RRI8")
    _decode_BBS = mnem("BBS", "RRI8")
    _decode_BBSI = mnem("BBSI", "RRI8",
                        inline0=lambda insn, _: insn.t + ((insn.r & 1) << 4))

    _st2_map = [
        "MOVI_N", "MOVI_N", "MOVI_N", "MOVI_N",
        "MOVI_N", "MOVI_N", "MOVI_N", "MOVI_N",
        "BEQZ_N", "BEQZ_N", "BEQZ_N", "BEQZ_N",
        "BNEZ_N", "BNEZ_N", "BNEZ_N", "BNEZ_N",
    ]
    @classmethod
    def _decode_ST2(cls, insn, insn_bytes):
        # Formats RI7 and RI6 (s, r vary)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._st2_map)

    _decode_MOVI_N = mnem("MOVI.N", "RI7",
                          inline0=lambda insn, _:
                               sign_extend(insn.imm7, 7) if
                               # Sign-extending the 7-bit value with the logical
                               # and of its two most significant bits
                               ((insn.imm7 >> 5) == 3) else
                               insn.imm7
                          )
    _decode_BEQZ_N = mnem("BEQZ.N", "RI6")
    _decode_BNEZ_N = mnem("BNEZ.N", "RI6")

    _st3_map = [
        "MOV_N", None, None, None, # None is reserved
        None, None, None, None,
        None, None, None, None,
        None, None, None, "S3",
    ]
    @classmethod
    def _decode_ST3(cls, insn, insn_bytes):
        # Format RRRN (t, s vary)
        return cls._do_tbl_layer(insn, insn_bytes, "r", cls._st3_map)

    _decode_MOV_N = mnem("MOV.N", "RRRN")

    _s3_map = [
        "RET_N", "RETW_N", "BREAK_N", "NOP_N",
        None, None, "ILL_N", None, # None is reserved
        None, None, None, None,
        None, None, None, None,
    ]
    @classmethod
    def _decode_S3(cls, insn, insn_bytes):
        # Format RRRN (no fields vary)
        return cls._do_tbl_layer(insn, insn_bytes, "t", cls._s3_map)

    _decode_RET_N = mnem("RET.N", "RRRN")
    _decode_RETW_N = mnem("RETW.N", "RRRN")
    _decode_BREAK_N = mnem("BREAK.N", "RRRN")
    _decode_NOP_N = mnem("NOP.N", "RRRN")
    _decode_ILL_N = mnem("ILL.N", "RRRN")

    # Here's where we do the per-format decoding. This isn't quite as useful as
    # I thought it would be, since Xtensa's instruction formats are not at all
    # rigid (they sneak immediates into whatever bits are available, as they
    # should).

    # We actually don't keep the instruction bytes around for the disassembly
    # stage, so everything has to be parsed out somewhere in the decoding stage.
    @classmethod
    def _decode_fmt_RRR(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.RRR
        # EXTUI uses op2 to encode part of its operation, so parse it here
        insn.op2 = decode_op2(insn_bytes)
        _decode_components(insn, insn_bytes, ["t", "s", "r"])

    @classmethod
    def _decode_fmt_RSR(cls, insn, insn_bytes):
        insn.instruction_type = InstructionType.RSR
        insn.length = 3
        _decode_components(insn, insn_bytes, ["t", "sr"])

    @classmethod
    def _decode_fmt_CALLX(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.CALLX
        _decode_components(insn, insn_bytes, ["n", "m", "s", "r"])

    @classmethod
    def _decode_fmt_RRI4(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.RRI4
        _decode_components(insn, insn_bytes, ["r", "s", "t", "imm4"])

    @classmethod
    def _decode_fmt_RRI8(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.RRI8
        _decode_components(insn, insn_bytes, ["r", "s", "t", "imm8"])

    @classmethod
    def _decode_fmt_RI16(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.RI16
        _decode_components(insn, insn_bytes, ["t", "imm16"])

    @classmethod
    def _decode_fmt_CALL(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.CALL
        _decode_components(insn, insn_bytes, ["n", "offset"])

    @classmethod
    def _decode_fmt_BRI8(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.BRI8
        _decode_components(insn, insn_bytes, ["r", "s", "m", "n", "imm8"])

    @classmethod
    def _decode_fmt_BRI12(cls, insn, insn_bytes):
        insn.length = 3
        insn.instruction_type = InstructionType.BRI12
        _decode_components(insn, insn_bytes, ["s", "m", "n", "imm12"])

    @classmethod
    def _decode_fmt_RRRN(cls, insn, insn_bytes):
        insn.length = 2
        insn.instruction_type = InstructionType.RRRN
        _decode_components(insn, insn_bytes, ["r", "s", "t"])

    @classmethod
    def _decode_fmt_RI7(cls, insn, insn_bytes):
        insn.length = 2
        insn.instruction_type = InstructionType.RI7
        _decode_components(insn, insn_bytes, ["s", "i", "imm7"])

    @classmethod
    def _decode_fmt_RI6(cls, insn, insn_bytes):
        insn.length = 2
        insn.instruction_type = InstructionType.RI6
        _decode_components(insn, insn_bytes, ["s", "i", "z", "imm6"])
