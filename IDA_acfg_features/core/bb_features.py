import idautils

from . import architecture




def get_bb_strings(bb, string_list):
    """
    Get strings in the basic block.

    Args:
        bb: a 'BasicBlock' instance

    Return:
        the list of strings
    """
    d_from = []
    strings = []
    for h in idautils.Heads(bb.va, bb.va + bb.size):
        for xf in idautils.DataRefsFrom(h):
            d_from.append(xf)
    for k in string_list:
        if k.ea in d_from:
            strings.append(str(k))
    return strings


def get_n_transfer_instrs(mnem_list, arch):
    """
    Get the number of transfer instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of transfer instructions
    """
    return len([m for m in mnem_list if m in architecture.ARCH_MNEM[arch]['transfer']])


def get_n_redirect_instrs(mnem_list, arch):
    """
    Get the num of conditional, unconditional, and call instructions.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of redirect instructions
    """
    temp_instrs = architecture.ARCH_MNEM[arch]['conditional'] | \
        architecture.ARCH_MNEM[arch]['unconditional'] | \
        architecture.ARCH_MNEM[arch]['call']

    return len([m for m in mnem_list if m in temp_instrs])


def get_n_call_instrs(mnem_list, arch):
    """
    Get the number of call instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of call instructions
    """
    return len([m for m in mnem_list if m in architecture.ARCH_MNEM[arch]['call']])


def get_n_arith_instrs(mnem_list, arch):
    """
    Get the number of arithmetic instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of arithmetic instructions
    """
    return len([m for m in mnem_list if m in architecture.ARCH_MNEM[arch]['arithmetic']])


def get_n_logic_instrs(mnem_list, arch):
    """
    Get the number of logic instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of logic instructions
    """
    return len([m for m in mnem_list if m in architecture.ARCH_MNEM[arch]['logic']])
