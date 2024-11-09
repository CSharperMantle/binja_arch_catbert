import typing as ty

from binaryninja import (
    BranchType,
    LowLevelILFunction,
    LowLevelILLabel,
    RegisterInfo,
    RegisterName,
)
from binaryninja.architecture import Architecture, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType
from binaryninja.lowlevelil import ExpressionIndex

from .disasm import Opcode, disasm, get_instr_len
from .view import VM_CODE_BASE, VM_DATA_BASE


class CatbertArch(Architecture):
    name = "Catbert"

    address_size = 8
    default_int_size = 8
    instr_alignment = 1
    max_instr_length = 3

    regs = {
        RegisterName("RO"): RegisterInfo(RegisterName("RO"), 8),
        RegisterName("SP"): RegisterInfo(RegisterName("SP"), 4),
    }
    stack_pointer = RegisterName("SP")

    flags = []
    flag_roles = {}

    def get_instruction_info(
        self, data: bytes, addr: int
    ) -> ty.Optional[InstructionInfo]:
        info = InstructionInfo()

        match get_instr_len(data[0]):
            case int() as l:
                instr_len = l
            case _:
                return None
        info.length = instr_len

        match disasm(data):
            case None:
                return None
            case (Opcode.JMP, target):
                assert target is not None
                info.add_branch(BranchType.UnconditionalBranch, VM_CODE_BASE + target)
            case (Opcode.JMPNZ, target):
                assert target is not None
                info.add_branch(BranchType.TrueBranch, VM_CODE_BASE + target)
                info.add_branch(BranchType.FalseBranch, addr + instr_len)
            case (Opcode.JMPZ, target):
                assert target is not None
                info.add_branch(BranchType.FalseBranch, VM_CODE_BASE + target)
                info.add_branch(BranchType.TrueBranch, addr + instr_len)
            case (Opcode.HLT0, _) | (Opcode.HLT1, _):
                info.add_branch(BranchType.FunctionReturn)

        return info

    def get_instruction_text(
        self, data: bytes, addr: int
    ) -> ty.Optional[ty.Tuple[ty.List[InstructionTextToken], int]]:
        match get_instr_len(data[0]):
            case int() as l:
                instr_len = l
            case _:
                return None

        match disasm(data):
            case None:
                return None
            case (Opcode.SETF1, _) | (Opcode.SETF2, _) as v:
                assert v[1] is None
                tokens = [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, v[0].name.lower()
                    ),
                    InstructionTextToken(InstructionTextTokenType.TextToken, " "),
                    InstructionTextToken(InstructionTextTokenType.RegisterToken, "RO"),
                ]
            case (
                (Opcode.JMP, target)
                | (Opcode.JMPNZ, target)
                | (Opcode.JMPZ, target) as v
            ):
                assert target is not None
                tokens = [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, v[0].name.lower()
                    ),
                    InstructionTextToken(InstructionTextTokenType.TextToken, " "),
                    InstructionTextToken(
                        InstructionTextTokenType.PossibleAddressToken,
                        hex(target),
                        value=target,
                    ),
                ]
            case v:
                if v is None:
                    return None
                tokens = [
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, v[0].name.lower()
                    )
                ]
                if v[1] is not None:
                    tokens.extend(
                        (
                            InstructionTextToken(
                                InstructionTextTokenType.TextToken, " "
                            ),
                            InstructionTextToken(
                                InstructionTextTokenType.IntegerToken,
                                hex(v[1]),
                                value=v[1],
                            ),
                        )
                    )

        return tokens, instr_len

    def get_instruction_low_level_il(
        self, data: bytes, addr: int, il: LowLevelILFunction
    ) -> ty.Optional[int]:
        match get_instr_len(data[0]):
            case int() as l:
                instr_len = l
            case _:
                return None
        match disasm(data):
            case (Opcode.HLT0, _) | (Opcode.HLT1, _):
                il.append(il.no_ret())
            case (Opcode.PUSHI, imm):
                assert imm is not None
                il.append(il.push(8, il.const(8, imm)))
            case (Opcode.PUSHM, imm):
                assert imm is not None
                il.append(il.push(8, il.load(8, il.const(8, VM_DATA_BASE + imm * 8))))
            case (Opcode.ADDM, imm):
                assert imm is not None
                x = il.pop(8)
                y = il.load(8, il.const(8, VM_DATA_BASE + imm * 8))
                il.append(il.add(8, x, y))
            case (Opcode.STI, imm):
                assert imm is not None
                x = il.pop(8)
                il.append(il.store(8, il.const(8, VM_DATA_BASE + imm * 8), x))
            case (Opcode.LD, _):
                x = il.add(
                    8, il.const(8, VM_DATA_BASE), il.mult(8, il.pop(8), il.const(8, 8))
                )
                il.append(il.push(8, il.load(8, x)))
            case (Opcode.ST, _):
                x = il.pop(8)
                y = il.add(
                    8, il.const(8, VM_DATA_BASE), il.mult(8, il.pop(8), il.const(8, 8))
                )
                il.append(il.store(8, y, x))
            case (Opcode.DUP, _):
                x = il.pop(8)
                il.append(il.push(8, x))
                il.append(il.push(8, x))
            case (Opcode.POP, _):
                il.append(il.pop(8))
            case (Opcode.ADD, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.add(8, y, x)))
            case (Opcode.ADDI, imm):
                assert imm is not None
                x = il.pop(8)
                il.append(il.push(8, il.add(8, x, il.const(8, imm))))
            case (Opcode.SUB, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.sub(8, y, x)))
            case (Opcode.DIV, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.div_unsigned(8, y, x)))
            case (Opcode.MUL, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.mult(8, y, x)))
            case (Opcode.JMP, target):
                assert target is not None
                lbl = il.get_label_for_address(
                    Architecture[self.name], VM_CODE_BASE + target
                )
                il.append(
                    il.goto(lbl)
                    if lbl is not None
                    else il.jump(il.const_pointer(4, VM_CODE_BASE + target))
                )
            case (Opcode.JMPNZ, target):
                assert target is not None
                lbl = il.get_label_for_address(
                    Architecture[self.name], VM_CODE_BASE + target
                )
                lbl_nz, lbl_z = LowLevelILLabel(), LowLevelILLabel()
                x = il.pop(8)
                il.append(il.if_expr(x, lbl_nz, lbl_z))
                il.mark_label(lbl_nz)
                il.append(
                    il.goto(lbl)
                    if lbl is not None
                    else il.jump(il.const_pointer(4, VM_CODE_BASE + target))
                )
                il.mark_label(lbl_z)
            case (Opcode.JMPZ, target):
                assert target is not None
                lbl = il.get_label_for_address(
                    Architecture[self.name], VM_CODE_BASE + target
                )
                lbl_nz, lbl_z = LowLevelILLabel(), LowLevelILLabel()
                x = il.pop(8)
                il.append(il.if_expr(x, lbl_nz, lbl_z))
                il.mark_label(lbl_z)
                il.append(
                    il.goto(lbl)
                    if lbl is not None
                    else il.jump(il.const_pointer(4, VM_CODE_BASE + target))
                )
                il.mark_label(lbl_nz)
            case (Opcode.CMPE, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.compare_equal(8, y, x)))
            case (Opcode.CMPLT, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.compare_unsigned_less_than(8, y, x)))
            case (Opcode.CMPLE, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.compare_unsigned_less_equal(8, y, x)))
            case (Opcode.CMPGT, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.compare_unsigned_greater_than(8, y, x)))
            case (Opcode.CMPGE, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.compare_unsigned_greater_equal(8, y, x)))
            case (Opcode.CMPGEI, imm):
                assert imm is not None
                x = il.pop(8)
                il.append(
                    il.push(
                        8, il.compare_unsigned_greater_equal(8, x, il.const(8, imm))
                    )
                )
            case (Opcode.SETF1, _) | (Opcode.SETF2, _):
                x = il.pop(8)
                il.append(il.set_reg(8, RegisterName("RO"), x))
            case (Opcode.XOR, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.xor_expr(8, y, x)))
            case (Opcode.OR, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.or_expr(8, y, x)))
            case (Opcode.AND, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.and_expr(8, y, x)))
            case (Opcode.MOD, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.mod_unsigned(8, y, x)))
            case (Opcode.SHL, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.shift_left(8, y, x)))
            case (Opcode.SHR, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.logical_shift_right(8, y, x)))
            case (Opcode.ROL32, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.zero_extend(8, il.rotate_left(4, y, x))))
            case (Opcode.ROR32, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.zero_extend(8, il.rotate_right(4, y, x))))
            case (Opcode.ROL16, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.zero_extend(8, il.rotate_left(2, y, x))))
            case (Opcode.ROR16, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.zero_extend(8, il.rotate_right(2, y, x))))
            case (Opcode.ROL8, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.zero_extend(8, il.rotate_left(1, y, x))))
            case (Opcode.ROR8, _):
                x = il.pop(8)
                y = il.pop(8)
                il.append(il.push(8, il.zero_extend(8, il.rotate_right(1, y, x))))
            case None:
                return None
            case _:
                il.append(il.unimplemented())
        return instr_len


CatbertArch.register()
