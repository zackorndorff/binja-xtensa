import binascii
import bz2
from collections import namedtuple
import csv
import re

import pytest

from .instruction import Instruction, InstructionType, sign_extend
from .disassembly import disassemble_instruction, tokens_to_text

def test_decode_abs():
    # RRR type
    # ABS ar, at
    # 0110 0000 rrrr 0001 tttt 0000
    # 60        r1        t0
    # ABS a7, a9
    # 60 71 90 => 907160
    INSN_ABS = binascii.unhexlify("907160")
    insn = Instruction.decode(INSN_ABS)
    assert insn.op0 == 0
    assert insn.op1 == 0
    assert insn.op2 == 6
    assert insn.r == 7
    assert insn.t == 9
    assert insn.s == 1
    assert insn.length == 3
    assert insn.mnem == "ABS"
    assert insn.instruction_type == InstructionType.RRR

def test_decode_add():
    """
    ADD ar, as, at
    ADD a3, a2, a1

    * bit 23
    * 1000 # op2
    * 0000 # op1
    * 0011 # a3 is r
    * 0010 # a2 is s
    * 0001 # a1 is t
    * 0000 # op0
    * bit 0

    Thus our insn is 80 32 10, which must be byte swapped to 10 32 80
    """
    #EveryInstR Group
    insn = Instruction.decode(binascii.unhexlify("103280"))
    assert insn.op0 == 0
    assert insn.op1 == 0
    assert insn.op2 == 8
    assert insn.r == 3
    assert insn.s == 2
    assert insn.t == 1
    assert insn.length == 3
    assert insn.mnem == "ADD"
    assert insn.instruction_type == InstructionType.RRR

def test_add_narrow():
    """
    ADD.N ar, as, at
    * bit 15
    * rrrr
    * ssss
    * tttt
    * 1010 # op0
    * bit 0
    Requires Code Density Option

    ADD.N a9, a5, a3
    is then 1001 0101 0011 1010, or 953a, reversed to 3a95
    """
    INSN_ADD_N = binascii.unhexlify("3a95")
    insn = Instruction.decode(INSN_ADD_N)
    assert insn.op0 == 0b1010
    assert insn.t == 3
    assert insn.s == 5
    assert insn.r == 9
    assert insn.length == 2
    assert insn.mnem == "ADD.N"

def test_addi():
    """
    RRI8 type
    ADDI at, as, -128..127
    * bit 23
    * imm8 # check encoding of this
    * 1100
    * s
    * t
    * 0010
    * bit 0
    
    ADDI a11, a1, -2
    is then
    1111 1110 1100 0001 1011 0010, or fe c1 b2, reversed to b2c1fe
    """
    insn = Instruction.decode(binascii.unhexlify("b2c1fe"))
    assert insn.op0 == 0b0010
    assert insn.r == 0b1100
    assert insn.s == 1
    assert insn.t == 11
    # TODO: handle and test negative handling. I'd argue it should be a separate
    # value, as the decoded imm8 doesn't seem like a signed value
    #assert insn.imm8 == -2
    assert insn.imm8 == 0b11111110
    assert insn.length == 3
    assert insn.mnem == "ADDI"
    assert insn.instruction_type == InstructionType.RRI8


test_mnemonics_data = []
with bz2.open("test_mnemonics.csv.bz2", "rt") as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        opcode = row[0]
        mnem = row[1]
        opbytes = binascii.unhexlify(opcode)
        test_mnemonics_data.append((opbytes, mnem.strip()))


def test_mnemonics_data_is_valid():
    assert len(test_mnemonics_data) > 0
    assert len(test_mnemonics_data[0]) == 2

def compare_mnem(one, two):
    to_compare = []
    for it in (one, two):
        if (it.startswith("rsr.") or
            it.startswith("wsr.") or
            it.startswith("xsr.")):
                # Work around not having the register names for special regs
                it = it[:3]
        it = it.lower().strip()
        to_compare.append(it)
    one, two = to_compare
    return one == two


@pytest.mark.parametrize("opbytes,mnem_expected", test_mnemonics_data)
def test_mnem_from_file(opbytes, mnem_expected):
    insn = Instruction.decode(opbytes)
    assert insn.length == len(opbytes)
    assert compare_mnem(insn.mnem, mnem_expected)

mtd_re = r'([0-9a-f]+):\s+([0-9a-f]+)\s+([a-z0-9.]+)\s+(.*)$'
mtd_rec = re.compile(mtd_re)
with bz2.open("test_mnemonic_text.dump.bz2", "rt") as fp:
    mnem_text_dump = fp.readlines()

def bswap_opcode_string(opstr):
    data = binascii.unhexlify(opstr)
    reverse_data = bytearray(data)
    reverse_data.reverse()
    return binascii.hexlify(reverse_data).decode('utf-8')

DisassLine = namedtuple('DisassLine', ['addr', 'opcode', 'mnem', 'rest'])

def parse_test_data(data_lines):
    newdata = []
    for line in data_lines:
        match_obj = mtd_rec.match(line)
        assert match_obj
        addr, opcode, mnem, rest = match_obj.groups()
        opcode = bswap_opcode_string(opcode)
        assert len(addr)
        assert len(opcode)
        assert len(mnem)
        newdata.append(DisassLine(addr, opcode, mnem, rest))
    return newdata

def test_mtd_re():
    data = parse_test_data(mnem_text_dump)
    assert len(data) > 0
    assert len(data[0]) == 4

def _normalize_insn(it):
    it = it.replace("\t", "").lower()
    tokens = []
    for tok in it.split():
        tok = tok.replace(",", "")
        if tok.startswith("0x"):
            tokens.append(str(sign_extend(int(tok, 0), 32)))
        else:
            tokens.append(tok)
    return ''.join(tokens)

def compare_insn(one, two):
    one = _normalize_insn(one)
    two = _normalize_insn(two)

    return one == two

def test_tokens_to_text():
    INSN_ABS = binascii.unhexlify("907160")
    insn = Instruction.decode(INSN_ABS)
    disass_text = tokens_to_text(disassemble_instruction(insn, 0))
    assert compare_insn(disass_text, "ABS    a7, a9")
    assert compare_insn(disass_text, "abs a7, a9")

mtd_data = parse_test_data(mnem_text_dump)
# mnem_text_dump is a bunch of dumped disassembly, uniq'd on the mnem for
# brevity
@pytest.mark.parametrize("parsed_line", mtd_data)
def test_mnem_text_dump(parsed_line):
    insn = Instruction.decode(binascii.unhexlify(parsed_line.opcode))
    assert compare_mnem(insn.mnem, parsed_line.mnem)

    addr = int(parsed_line.addr, 16)
    disass_text = tokens_to_text(disassemble_instruction(insn, addr))

    expected_insn_text = (parsed_line.mnem + " " + parsed_line.rest).strip()

    assert compare_insn(expected_insn_text, disass_text)

with bz2.open("torture_test.dump.bz2", "rt") as fp:
    lots_text_dump = fp.readlines()
lots_data = parse_test_data(lots_text_dump)
# lots_text_dump is a bunch of dumped disassembly, uniq'd on the mnem for
# brevity
@pytest.mark.parametrize("parsed_line", lots_data)
def test_lots_text_dump(parsed_line):
    insn = Instruction.decode(binascii.unhexlify(parsed_line.opcode))
    assert compare_mnem(insn.mnem, parsed_line.mnem)

    addr = int(parsed_line.addr, 16)
    disass_text = tokens_to_text(disassemble_instruction(insn, addr))

    expected_insn_text = (parsed_line.mnem + " " + parsed_line.rest).strip()

    assert compare_insn(expected_insn_text, disass_text)

with bz2.open("esp32_torture_test.dump.bz2", "rt") as fp:
    esp32_lots_text_dump = fp.readlines()
esp32_lots_data = parse_test_data(esp32_lots_text_dump)
# lots_text_dump is a bunch of dumped disassembly, uniq'd on the mnem for
# brevity
@pytest.mark.parametrize("esp32_parsed_line", esp32_lots_data)
def test_lots_text_dump(esp32_parsed_line):
    if esp32_parsed_line.mnem in ['rer', 'wer']:
        # I disagree with objdump here; the manual states that these insns take
        # arguments; objdump doesn't appear to think so? Also possible my
        # cleanup of the output broke the objdump results?
        pytest.xfail()
    insn = Instruction.decode(binascii.unhexlify(esp32_parsed_line.opcode))
    assert compare_mnem(insn.mnem, esp32_parsed_line.mnem)

    addr = int(esp32_parsed_line.addr, 16)
    disass_text = tokens_to_text(disassemble_instruction(insn, addr))

    expected_insn_text = (esp32_parsed_line.mnem + " " + esp32_parsed_line.rest).strip()

    assert compare_insn(expected_insn_text, disass_text)
