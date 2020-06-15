"""
Xtensa lifting to BNIL

Here we provide a `lift` function that takes a decoded instruction and an
address where that instruction is, and we return BNIL.
"""
from binaryninja import Architecture, LowLevelILLabel

from .instruction import sign_extend

def _reg_name(insn, fmt):
    """Get the concrete register for a particular part of an instruction

    For example, if the docs say an instruction writes to "as", we call this
    function, which will check the `s` decoded control signal (say it's "7") and
    return "a7" for passing to BNIL.
    """
    if fmt.startswith("a"):
        rest = fmt[1:]
        val = getattr(insn, rest, None)
        if val is None:
            raise Exception("Could not find property " + fmt)
        return "a" + str(val)
    else:
        # When we lift boolean instructions, we'll need to add support for "b"
        # registers, etc.
        raise Exception("Unimplemented reg name fmt: " + fmt)

def lift(insn, addr, il):
    """Dispatch function for lifting

    Looks up _lift_MNEM() in the current global namespace (I think that's just
    the module level?) and calls it if it exists, otherwise we say the
    instruction is unimplemented.
    """
    try:
        # We replace the "." in mnemonics with a "_", as we do in several other
        # places in the code.
        # At some point, this should become a property of the Instruction.
        func = globals()["_lift_" + insn.mnem.replace(".", "_")]
    except KeyError:
        il.append(il.unimplemented())
        return insn.length

    return func(insn, addr, il)

# Helpers for some shared code between instructions

def _lift_cond(cond, insn, addr, il):
    """Helper for lifting conditional jumps
    
    We pass in an IL condition (LowLevelILExpr) and this function lifts a IL
    conditional that will jump to `insn.target_offset(addr)` if the condition is
    true, otherwise we continue to the next instruction.
    """
    true_label = il.get_label_for_address(Architecture['xtensa'],
                                           insn.target_offset(addr))
    false_label = il.get_label_for_address(Architecture['xtensa'],
                                          addr + insn.length)
    must_mark_true = False
    if true_label is None:
        true_label = LowLevelILLabel()
        must_mark_true = True

    must_mark_false = False
    if false_label is None:
        false_label = LowLevelILLabel()
        must_mark_false = True

    il.append(
        il.if_expr(cond,
                   true_label,
                   false_label
                   ))
    if must_mark_true:
        il.mark_label(true_label)
        il.append(il.jump(il.const(4, insn.target_offset(addr))))
    if must_mark_false:
        il.mark_label(false_label)
        il.append(il.jump(il.const(4, addr + insn.length)))
    return insn.length

def _lift_cmov(cond, insn, addr, il):
    """Helper for lifting conditional moves
    
    We pass in an IL condition (LowLevelILExpr) and this function lifts a move
    from as to ar if the condition is true. In either case we then continue with
    the next instruction after the (potential) move.
    """
    true_label = LowLevelILLabel()
    false_label = LowLevelILLabel()
    il.append(il.if_expr(cond, true_label, false_label))
    il.mark_label(true_label)
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.reg(4, _reg_name(insn, "as"))))
    il.mark_label(false_label)
    return insn.length

def _lift_addx(x_bits, insn, addr, il):
    """Helper for ADDX2, ADDX4, ADDX8"""
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.shift_left(4,
                                        il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, x_bits)),
                          il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_subx(x_bits, insn, addr, il):
    """Helper for SUBX2, SUBX4, SUBX8"""
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.sub(4,
                          il.shift_left(4,
                                        il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, x_bits)),
                          il.reg(4, _reg_name(insn, "at")))))
    return insn.length

# From here on down, I lifted instructions in priority order of how much
# analysis it would get me. So I started with branches and common math and
# worked my way down the frequency list.

def _lift_CALL0(insn, addr, il):
    dest = il.const(4, insn.target_offset(addr))
    il.append(
        il.call(dest))
    return insn.length

def _lift_CALLX0(insn, addr, il):
    dest = il.reg(4, _reg_name(insn, "as"))
    il.append(
        il.call(dest))
    return insn.length

def _lift_RET(insn, addr, il):
    dest = il.reg(4, 'a0')
    il.append(il.ret(dest))
    return insn.length

_lift_RET_N = _lift_RET

def _lift_L32I_N(insn, addr, il):
    _as = il.reg(4, _reg_name(insn, "as"))
    imm = il.const(4, insn.inline0(addr))
    va = il.add(4, _as, imm)
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.load(4, va)
                   ))
    return insn.length

def _lift_L32R(insn, addr, il):
    va = il.const(4, insn.mem_offset(addr))
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.load(4, va)
                   ))
    return insn.length

def _lift_S32I_N(insn, addr, il):
    _as = il.reg(4, _reg_name(insn, "as"))
    imm = il.const(4, insn.inline0(addr))
    va = il.add(4, _as, imm)
    il.append(
        il.store(4, va, il.reg(4, "a" + str(insn.t))))
    return insn.length

def _lift_MOVI_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "as"),
                   il.const(4, insn.inline0(addr))
                   ))
    return insn.length

def _lift_MOV_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.reg(4, _reg_name(insn, "as"))
                   ))
    return insn.length

def _lift_ADDI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.const(4, insn.simm8())
                          )))
    return insn.length

def _lift_L8UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.imm8))
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.zero_extend(4,
                                  il.load(1, va))))
    return insn.length

def _lift_S32I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(
        il.store(4, va, il.reg(4, _reg_name(insn, "at"))))
    return insn.length

def _lift_L32I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.load(4, va)))
    return insn.length

def _lift_L16SI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.sign_extend(4, il.load(2, va))))
    return insn.length

def _lift_L16UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.zero_extend(4, il.load(2, va))))
    return insn.length

def _lift_J(insn, addr, il):
    il.append(il.jump(il.const(4, insn.target_offset(addr))))
    return insn.length

def _lift_CALLX0(insn, addr, il):
    il.append(
        il.call(il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _lift_JX(insn, addr, il):
    il.append(il.jump(il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _lift_S8I(insn, addr, il):
    il.append(il.store(1, il.add(4,
                                 il.reg(4, _reg_name(insn, "as")),
                                 il.const(4, insn.imm8)),
                       il.low_part(1, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_MOVI(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.const(4, insn.inline0(addr))))
    return insn.length

def _lift_EXTUI(insn, addr, il):
    inp = il.reg(4, _reg_name(insn, "at"))

    mask = (2 ** insn.inline1(addr)) - 1
    mask_il = il.const(4, mask)

    shiftimm = insn.extui_shiftimm()
    if shiftimm:
        shift_il = il.const(1, shiftimm)
        shifted = il.logical_shift_right(4, inp, shift_il)
        anded = il.and_expr(4, shifted, mask_il)
    else:
        # If we don't have to shift (thus shiftimm should be 0), then don't emit
        # the IL for it
        anded = il.and_expr(4, inp, mask_il)

    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         anded
                         ))
    return insn.length

def _lift_OR(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.or_expr(4,
                              il.reg(4, _reg_name(insn, "as")),
                              il.reg(4, _reg_name(insn, "at"))
                              )))
    return insn.length

def _lift_MEMW(insn, addr, il):
    il.append(
        il.intrinsic([], "memw", [])
    )
    return insn.length

def _lift_ADDI_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                       il.reg(4, _reg_name(insn, "as")),
                       il.const(4, insn.inline0(addr))
                   )))
    return insn.length

def _lift_SLLI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.shift_left(4,
                       il.reg(4, _reg_name(insn, "as")),
                       il.const(1, insn.inline0(addr))
                       )))
    return insn.length

def _lift_ADD_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_BEQZ_N(insn, addr, il):
    cond = il.compare_equal(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_AND(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.and_expr(4,
                              il.reg(4, _reg_name(insn, "as")),
                              il.reg(4, _reg_name(insn, "at"))
                              )))
    return insn.length

_lift_BEQZ = _lift_BEQZ_N

def _lift_L16UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.zero_extend(4, il.load(2, va))))
    return insn.length

def _lift_BNEZ(insn, addr, il):
    cond = il.compare_not_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

_lift_BNEZ_N = _lift_BNEZ

def _lift_BEQZ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

_lift_BEQZ_N = _lift_BEQZ

def _lift_BNEI(insn, addr, il):
    cond = il.compare_not_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, insn.b4const()))
    return _lift_cond(cond, insn, addr, il)

def _lift_BEQI(insn, addr, il):
    cond = il.compare_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, insn.b4const()))
    return _lift_cond(cond, insn, addr, il)

def _lift_BALL(insn, addr, il):
    cond = il.compare_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "at")),
                                il.not_expr(4, il.reg(4, _reg_name(insn, "as")))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNALL(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "at")),
                                il.not_expr(4, il.reg(4, _reg_name(insn, "as")))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BANY(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNONE(insn, addr, il):
    cond = il.compare_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBC(insn, addr, il):
    cond = il.compare_equal(4,
                            il.test_bit(4,
                                il.reg(4, _reg_name(insn, "as")),
                                # Strictly speaking we're supposed to check the
                                # low 5 bits of at. I don't really see the need
                                # to clutter the UI with it

                                # Also: TODO: figure out which way Binja numbers
                                # the bits
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBS(insn, addr, il):
    cond = il.test_bit(4,
        il.reg(4, _reg_name(insn, "as")),
        # Strictly speaking we're supposed to check the
        # low 5 bits of at. I don't really see the need
        # to clutter the UI with it
        il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBCI(insn, addr, il):
    cond = il.compare_equal(4,
                            il.test_bit(4,
                                il.reg(4, _reg_name(insn, "as")),
                                # Also: TODO: figure out which way Binja numbers
                                # the bits
                                il.const(4, insn.inline0(addr))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBSI(insn, addr, il):
    cond = il.test_bit(4,
        il.reg(4, _reg_name(insn, "as")),
        il.const(4, insn.inline0(addr)))
    return _lift_cond(cond, insn, addr, il)

def _lift_BEQ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNE(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BGE(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.reg(4, _reg_name(insn, "at"))
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEU(insn, addr, il):
    cond = il.compare_unsigned_greater_equal(4,
                                             il.reg(4, _reg_name(insn, "as")),
                                             il.reg(4, _reg_name(insn, "at"))
    )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEI(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, insn.b4const())
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEUI(insn, addr, il):
    cond = il.compare_unsigned_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, insn.b4constu())
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEZ(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BLT(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.reg(4, _reg_name(insn, "at"))
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTU(insn, addr, il):
    cond = il.compare_unsigned_less_than(4,
                                         il.reg(4, _reg_name(insn, "as")),
                                         il.reg(4, _reg_name(insn, "at"))
                                         )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTI(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.const(4, insn.b4const())
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTUI(insn, addr, il):
    cond = il.compare_unsigned_less_than(4,
                                         il.reg(4, _reg_name(insn, "as")),
                                         il.const(4, insn.b4constu())
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTZ(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_SUB(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.sub(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_ADD(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_XOR(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.xor_expr(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_S16I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr))
                )
    il.append(
        il.store(2, va,
                 il.low_part(2, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_SRAI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.arith_shift_right(4,
                                        il.reg(4, _reg_name(insn, "at")),
                                        il.const(4, insn.inline0(addr)))))
    return insn.length

def _lift_ADDX2(insn, addr, il):
    return _lift_addx(1, insn, addr, il)

def _lift_ADDX4(insn, addr, il):
    return _lift_addx(2, insn, addr, il)

def _lift_ADDX8(insn, addr, il):
    return _lift_addx(3, insn, addr, il)

def _lift_SUBX2(insn, addr, il):
    return _lift_subx(1, insn, addr, il)

def _lift_SUBX4(insn, addr, il):
    return _lift_subx(2, insn, addr, il)

def _lift_SUBX8(insn, addr, il):
    return _lift_subx(3, insn, addr, il)

def _lift_SRLI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.logical_shift_right(4,
                                          il.reg(4, _reg_name(insn, "at")),
                                          il.const(4, insn.s))))
    return insn.length

def _lift_ADDMI(insn, addr, il):
    constant = sign_extend(insn.imm8, 8) << 8
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.const(4, constant))))
    return insn.length

def _lift_MULL(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.reg(4, _reg_name(insn, "as")),
                           il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_NEG(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.neg_expr(4, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_SYSCALL(insn, addr, il):
    il.append(il.system_call())
    return insn.length

def _lift_MOVEQZ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVNEZ(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVGEZ(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVLTZ(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_SSL(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.sub(1,
                                il.const(1, 32),
                                il.low_part(1, il.reg(4, _reg_name(insn, "as")))
                                )))
    return insn.length

def _lift_SSR(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.low_part(1, il.reg(4, _reg_name(insn, "as")))))
    return insn.length

def _lift_SSAI(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.const(1, insn.inline0(addr))))
    return insn.length

def _lift_SLL(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.shift_left(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.reg(1, "sar"))))
    return insn.length

def _lift_SRL(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.logical_shift_right(4,
                                                il.reg(4, _reg_name(insn, "at")),
                                                il.reg(1, "sar"))))
    return insn.length

def _lift_SRC(insn, addr, il):
    operand = il.reg_split(8,
                           _reg_name(insn, "as"),
                           _reg_name(insn, "at"))
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.low_part(4,
                                     il.logical_shift_right(8,
                                                            operand,
                                                            il.reg(1, "sar"))
                                     )))
    return insn.length

def _lift_SSA8L(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         # Low part is not strictly correct... but good enough
                         il.shift_left(1,
                                       il.low_part(1, il.reg(4, _reg_name(insn, "as"))),
                                       il.const(1, 3))))
    return insn.length

def _lift_SRA(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.arith_shift_right(4,
                                              il.reg(4, _reg_name(insn, "at")),
                                              il.reg(1, "sar"))))
    return insn.length

def _lift_ISYNC(insn, addr, il):
    il.append(
        il.intrinsic([], "isync", [])
    )
    return insn.length

def _lift_ILL(insn, addr, il):
    # TODO: pick a proper trap constant
    il.append(il.trap(0))
    return insn.length

def _lift_MUL16S(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.sign_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "as")))),
                           il.sign_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "at"))))
                           )))
    return insn.length

def _lift_MUL16U(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.zero_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "as")))),
                           il.zero_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "at"))))
                           )))
    return insn.length
