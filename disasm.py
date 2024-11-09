import enum
import typing as ty


class Opcode(enum.IntEnum):
    HLT0 = 0x00
    PUSHI = 0x01
    PUSHM = 0x02
    ADDM = 0x03
    STI = 0x04
    LD = 0x05
    ST = 0x06
    DUP = 0x07
    POP = 0x08
    ADD = 0x09
    ADDI = 0x0A
    SUB = 0x0B
    DIV = 0x0C
    MUL = 0x0D
    JMP = 0x0E
    JMPNZ = 0x0F
    JMPZ = 0x10
    CMPE = 0x11
    CMPLT = 0x12
    CMPLE = 0x13
    CMPGT = 0x14
    CMPGE = 0x15
    CMPGEI = 0x16
    SETF1 = 0x17
    HLT1 = 0x18
    SETF2 = 0x19
    XOR = 0x1A
    OR = 0x1B
    AND = 0x1C
    MOD = 0x1D
    SHL = 0x1E
    SHR = 0x1F
    ROL32 = 0x20
    ROR32 = 0x21
    ROL16 = 0x22
    ROR16 = 0x23
    ROL8 = 0x24
    ROR8 = 0x25
    OUTB = 0x26


def get_instr_len(
    op: int,
) -> ty.Optional[ty.Literal[1, 3]]:
    match op:
        case (
            Opcode.ADDI
            | Opcode.JMPNZ
            | Opcode.JMPZ
            | Opcode.JMP
            | Opcode.PUSHI
            | Opcode.PUSHM
            | Opcode.ADDM
            | Opcode.STI
        ):
            return 3
        case _:
            return 1


def disasm(
    data: bytes,
) -> ty.Optional[tuple[Opcode, ty.Optional[int]]]:
    if len(data) < 1:
        return None

    op = data[0]
    instr_len = get_instr_len(op)
    if instr_len is None or len(data) < instr_len:
        return None

    if op not in (m.value for m in Opcode):
        return None

    match op:
        case (
            Opcode.ADDI
            | Opcode.JMPNZ
            | Opcode.JMPZ
            | Opcode.JMP
            | Opcode.PUSHI
            | Opcode.PUSHM
            | Opcode.ADDM
            | Opcode.STI
        ):
            return (Opcode(op), int.from_bytes(data[1:3], "big"))
        case _:
            return (Opcode(op), None)
