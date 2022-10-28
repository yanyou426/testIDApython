import ctypes
import hashlib
import idaapi
import idautils
import idc
import json
import networkx as nx
import ntpath
import os
import pickle
import time
import ida_pro
import base64
from capstone import *
from collections import namedtuple
from matplotlib import pyplot
from copy import deepcopy

M_MAX = 0x49  # first unused opcode

func_struct = namedtuple('func_struct', 'func_name opt_level version compiler bb_size byte_size CFG ARCH LIB_NAME OBF bin_type file_path')
BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs'])
zlib_bow = ['mov', 'add', 'cmp', 'ld', 'ldr', 'sub', 'jmp', 'push', 'lea', 'je', 'nop', 'call', 'test', 'movzx', 'jne', 'pop', 'b', 'daddiu', 'addiu', 'xor', 'lw', 'str', 'sd', 'move', 'daddu', 'and', 'sw', 'ret', 'movz', 'beqz', 'movdqa', 'shl', 'shr', 'movaps', 'bl', 'or', 'bnez', 'cbz', 'ldp', 'ldur', 'dext', 'dsll', 'lbu', 'ja', 'jb', 'ldrb', 'stp', 'bal', 'b.ne', 'inc', 'jalr', 'movn', 'jae', 'jbe', 'lhu', 'movdqu', 'ldrh', 'b.eq', 'lsl', 'palignr', 'sltu', 'andi', 'bne', 'sll', 'subu', 'adrp', 'sb', 'sh', 'strb', 'cbnz', 'jr', 'strh', 'dec', 'lsr', 'beq', 'sltiu', 'addu', 'lui', 'jle', 'movq', 'movsxd', 'dsubu', 'stur', 'subs', 'js', 'not', 'movups', 'lddqu', 'jge', 'lwu', 'csel', 'sllv', 'b.hi', 'jl', 'sar', 'b.ls', 'jg', 'eor', 'sbb', 'adc', 'neg', 'dsrl', 'sete', 'mul', 'vmovups', 'cmn', 'endbr32', 'orr', 'b.hs', 'cmove', 'endbr64', 'b.lo', 'por', 'setne', 'imul', 'cmovb', 'ud2', 'movntdq', 'slti', 'tbnz', 'dsllv', 'slt', 'movabs', 'cmova', 'cset', 'srl', 'pslldq', 'blr', 'b.le', 'psrldq', 'ori', 'bltz', 'cmovne', 'ccmp', 'cmovbe', 'ubfx', 'movsd', 'ldrsw', 'sxth', 'seh', 'div', 'asr', 'sdl', 'sdr', 'tbz', 'dsrlv', 'ldl', 'movk', 'ldurb', 'b.gt', 'cmovae', 'sxtw', 'leave', 'cpuid', 'prefetcht0', 'b.lt', 'srlv', 'prefetchnta', 'b.ge', 'jns', 'mvn', 'rep', 'fld', 'cdqe', 'ext', 'movsx', 'vmovaps', 'prefetcht1', 'fstp', 'srav', 'blez', 'mflo', 'movntq', 'tst', 'cmovge', 'nor', 'mfhi', 'shld', 'bic', 'seta', 'dsll32', 'xori', 'xorps', 'movsb', 'dsra', 'lb', 'setb', 'vmovntdq', 'bgez', 'sturb', 'shrd', 'movd', 'fmul', 'dmultu', 'psubd', 'b.mi', 'dmult', 'sfence', 'cmovg', 'ubfiz']
curl_bow = ['mov', 'call', 'push', 'test', 'je', 'jmp', 'cmp', 'lea', 'add', 'jne', 'pop', 'xor', 'sub', 'movzx', 'ret', 'and', 'or', 'ja', 'nop', 'inc', 'movsxd', 'shl', 'cmove', 'movaps', 'shr', 'jle', 'jg', 'jb', 'setne', 'cmovne', 'movsx', 'movabs', 'jae', 'js', 'jbe', 'dec', 'imul', 'jl', 'sete', 'sbb', 'endbr64', 'endbr32', 'movups', 'bt', 'sar', 'jge', 'not', 'leave', 'jns', 'adc', 'repne', 'scasb', 'neg', 'xorps', 'idiv', 'cdqe', 'cmovg', 'movsd', 'cvtsi2sd', 'div', 'rep', 'cqo', 'cdq', 'mul', 'cmovge', 'cmovl', 'cmovs', 'fstp', 'seta', 'cmovae', 'cmova', 'movdqu', 'fild', 'cmovb', 'rol', 'setg', 'pxor', 'fld', 'cmovle', 'divsd', 'cmovbe', 'setb', 'bswap', 'stosd', 'movq', 'repe', 'cmpsb', 'cvttsd2si', 'fldcw', 'movdqa', 'movsb', 'setae', 'mulsd', 'shrd', 'pcmpeqd', 'cmovns', 'fistp', 'bts', 'setl', 'pshufd', 'fnstcw', 'punpcklqdq', 'ucomisd', 'shld', 'fdiv', 'sets', 'setbe', 'stosq', 'paddq', 'fxch', 'fdivp', 'setle', 'xchg', 'fmul', 'bsr', 'cwde', 'movapd', 'pand', 'ror', 'punpcklwd', 'movsq', 'setge', 'por', 'comisd', 'movd', 'punpcklbw', 'fldz', 'setns', 'fld1', 'fchs', 'psubq', 'btr', 'seto', 'fcomi', 'pcmpeqb', 'fcomip', 'fdivrp', 'fucomi', 'fmulp', 'punpckhwd', 'xorpd', 'fucomip', 'movhps', 'punpckldq', 'punpckhdq', 'psrlw', 'packuswb', 'pslld', 'stosb', 'punpckhqdq']
openssl_bow = ['mov', 'ld', 'push', 'add', 'call', 'move', 'ldr', 'daddiu', 'nop', 'sd', 'cmp', 'lea', 'bl', 'b', 'test', 'xor', 'je', 'jalr', 'movz', 'jmp', 'sub', 'pop', 'addiu', 'str', 'beqz', 'jne', 'adrp', 'ldp', 'cbz', 'ret', 'lw', 'stp', 'and', 'daddu', 'bnez', 'sw', 'ldur', 'bal', 'eor', 'cbnz', 'jr', 'movzx', 'b.eq', 'pxor', 'ror', 'b.ne', 'or', 'lui', 'stur', 'movdqa', 'sll', 'ldrb', 'jle', 'lbu', 'shr', 'beq', 'bne', 'dsll', 'andi', 'sb', 'shl', 'movups', 'dext', 'orr', 'movsxd', 'strb', 'adc', 'inc', 'movn', 'endbr64', 'lsr', 'movdqu', 'addu', 'jg', 'ja', 'sltu', 'lsl', 'subs', 'tbnz', 'blez', 'blr', 'sltiu', 'endbr32', 'jb', 'vpxor', 'rol', 'b.lt', 'mul', 'b.le', 'slt', 'cset', 'paddd', 'csel', 'js', 'sxtw', 'srl', 'jl', 'slti', 'movq', 'b.gt', 'dsubu', 'dec', 'rorx', 'ori', 'jbe', 'pand', 'shrd', 'rotr', 'dsrl', 'setne', 'jae', 'b.hi', 'ldrsw', 'paddq', 'jge', 'bswap', 'sar', 'vpaddd', 'xorps', 'movaps', 'psrlq', 'movabs', 'vmovdqu', 'bltz', 'sete', 'ubfx', 'tbz', 'psrld', 'aesenc', 'subu', 'cmove', 'por', 'pshufd', 'b.ls', 'imul', 'sbb', 'lb', 'b.lo', 'bgtz', 'psllq', 'not', 'ext', 'ccmp', 'b.ge', 'neg', 'movk', 'vpsrld', 'cdqe', 'pslld', 'vpaddq']

def parse_func(pfn, strlist):
    """
    Original code from BinaryAI (GPL-3.0):

    https://github.com/binaryai/sdk/blob/
    efcea6b27b36326f3de9ab6bfa0f668d3513e6c7/binaryai/ida/ida_feature.py#L115
    """
    try:
        hf = idaapi.hexrays_failure_t()
        cfunc = idaapi.decompile(pfn.start_ea, hf)
        mbr = idaapi.mba_ranges_t(pfn)
        mba = idaapi.gen_microcode(
            mbr,
            hf,
            None,
            idaapi.DECOMP_NO_WAIT,
            idaapi.MMAT_GLBOPT3
        )
    except Exception:
        return None
    if mba is None:
        return None

    func_bytes = 0
    for start, end in idautils.Chunks(pfn.start_ea):
        func_bytes += (end - start)
    # G.graph['hash'] = hashlib.md5(func_bytes).hexdigest()
    return func_bytes

def capstone_disassembly(md, ea, size, prefix):
    """Return the BB (normalized) disassembly, with mnemonics and BB heads."""
    try:
        bb_heads, bb_mnems, bb_disasm, bb_norm = list(), list(), list(), list()

        # Iterate over each instruction in the BB
        for i_inst in md.disasm(idc.get_bytes(ea, size), ea):
            # Get the address
            bb_heads.append(i_inst.address)
            # Get the mnemonic
            bb_mnems.append(i_inst.mnemonic)
            # Get the disasm
            bb_disasm.append("{} {}".format(
                i_inst.mnemonic,
                i_inst.op_str))

            # Compute the normalized code. Ignore the prefix.
            # cinst = prefix + i_inst.mnemonic
            cinst = i_inst.mnemonic

            # Iterate over the operands
            for op in i_inst.operands:

                # Type register
                if (op.type == 1):
                    cinst = cinst + " " + i_inst.reg_name(op.reg)

                # Type immediate
                elif (op.type == 2):
                    imm = int(op.imm)
                    if (-int(5000) <= imm <= int(5000)):
                        cinst += " " + str(hex(op.imm))
                    else:
                        cinst += " " + str('HIMM')

                # Type memory
                elif (op.type == 3):
                    # If the base register is zero, convert to "MEM"
                    if (op.mem.base == 0):
                        cinst += " " + str("[MEM]")
                    else:
                        # Scale not available, e.g. for ARM
                        if not hasattr(op.mem, 'scale'):
                            cinst += " " + "[{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.disp))
                        else:
                            cinst += " " + "[{}*{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.scale),
                                str(op.mem.disp))

                if (len(i_inst.operands) > 1):
                    cinst += ","

            # Make output looks better
            cinst = cinst.replace("*1+", "+")
            cinst = cinst.replace("+-", "-")

            if "," in cinst:
                cinst = cinst[:-1]
            cinst = cinst.replace(" ", "_").lower()
            bb_norm.append(str(cinst))

        return bb_heads, bb_mnems, bb_disasm, bb_norm

    except Exception as e:
        print("[!] Capstone exception", e)
        return list(), list(), list(), list()

def get_basic_blocks(fva):
    """Return the list of BasicBlock for a given function."""
    bb_list = list()
    func = idaapi.get_func(fva)
    if func is None:
        return bb_list
    for bb in idaapi.FlowChart(func):
        # WARNING: this function DOES NOT include the BBs with size 0
        # This is different from what IDA_acfg_features does.
        # if bb.end_ea - bb.start_ea > 0:
        if bb.end_ea - bb.start_ea > 0:
            bb_list.append(
                BasicBlock(
                    va=bb.start_ea,
                    size=bb.end_ea - bb.start_ea,
                    succs=[(x.start_ea, x.end_ea) for x in bb.succs()]))
    return bb_list

def initialize_capstone(procname, bitness):
    """
    Initialize the Capstone disassembler.
    Original code from Willi Ballenthin (Apache License 2.0):
    https://github.com/williballenthin/python-idb/blob/
    2de7df8356ee2d2a96a795343e59848c1b4cb45b/idb/idapython.py#L874
    """
    md = None
    prefix = "UNK_"

    # WARNING: mipsl mode not supported here
    if procname == 'mipsb':
        prefix = "M_"
        if bitness == 32:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
        if bitness == 64:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)

    if procname == "arm":
        prefix = "A_"
        if bitness == 32:
            # WARNING: THUMB mode not supported here
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        if bitness == 64:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    if "pc" in procname:
        prefix = "X_"
        if bitness == 32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        if bitness == 64:
            md = Cs(CS_ARCH_X86, CS_MODE_64)

    if md is None:
        raise RuntimeError(
            "Capstone initialization failure ({}, {})".format(
                procname, bitness))

    # Set detail to True to get the operand detailed info
    md.detail = True
    return md, prefix

def get_bb_disasm(bb, md, prefix):
    """Return the (nomalized) disassembly for a BasicBlock."""
    b64_bytes = base64.b64encode(idc.get_bytes(bb.va, bb.size))
    bb_heads, bb_mnems, bb_disasm, bb_norm = \
        capstone_disassembly(md, bb.va, bb.size, prefix)
    return b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm

def get_bitness():
    """Return 32/64 according to the binary bitness."""
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 64
    elif info.is_32bit():
        return 32

def generate_cfg(idb_path, fva_list, output_dir):
    print("[D] Processing: %s" % idb_path)
    # pic = nx.DiGraph()
    # Create the output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_name = ntpath.basename(
        idb_path.replace(".i64", "").replace(".idb", ""))
    output_name += "_graph.pkl"
    output_path = os.path.join(output_dir, output_name)
    procname = idaapi.get_inf_structure().procname.lower()
    bitness = get_bitness()

    graph_dict = dict()
    strlist = [i.ea for i in idautils.Strings()]
    # print(strlist) # a string of address
    md, prefix = initialize_capstone(procname, bitness)

    # For each function in the list
    # test_func = 91016 # 4 basic blocks but exists one bb with 0 size
    for fva in fva_list:
    # for x in range(1):
    #     print("fva:{}".format(fva))
        try:
            pfn = idaapi.get_func(fva)
            # print(pfn)
            # The decompiler assumes that the segment '.got' is read-only because of its NAME.
            funcbytes = parse_func(pfn, strlist)
            if funcbytes is None:
                continue

            # get feature vector of each bb and thus generating a cfg as the nx struct
            cfg = nx.DiGraph()
            bb_ind = 0
            bb_list = []
            add2ind = {}
            for bb in get_basic_blocks(fva):
                # CFG
                # print(bb.va)
                add2ind[bb.va] = bb_ind
                # print("The index of basic block {} is {}".format(bb.va, bb_ind))
                bb_ind += 1
                # nodes_set.add(bb.va)
                # for dest_ea in bb.succs:
                #     edges_set.add((bb.va, dest_ea))
                # BB-level features
                list_zlib = [0] * len(zlib_bow)
                # print("bb size is {}".format(bb.size))
                if bb.size:
                    b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = \
                        get_bb_disasm(bb, md, prefix)
                    # print(b64_bytes)
                    opcode_list = bb_mnems

                    for str_op in opcode_list:
                        if str_op in zlib_bow:
                            list_zlib[zlib_bow.index(str_op)] += 1
                        else:
                            print("out of words in zlib when dealing with opcode {}".format(str_op))


                # print(list_zlib)
                tmp_dic = {"feature": list_zlib}
                bb_list.append((bb_ind - 1, tmp_dic))

            # print("node load finished!")
            cfg.add_nodes_from(bb_list)


            edge_list = []
            for bb in get_basic_blocks(fva):
                cur_ind = add2ind[bb.va]
                for dest_block in bb.succs:
                    if dest_block[0] in add2ind.keys():
                        next_ind = add2ind[dest_block[0]]
                        edge_list.append((cur_ind, next_ind))
                    else:
                        unreachable_bb_size = dest_block[1] - dest_block[0]
                        if unreachable_bb_size != 0:
                            print("error when loading the edge to {}".format(dest_block[0]))
            cfg.add_edges_from(edge_list)
            func_name = idaapi.get_func_name(fva)
            # print("The cfg length of {} is {}".format(func_name, len(cfg)))
            tmp_func_struct = func_struct(
                func_name=func_name,
                opt_level=None,
                version=None,
                compiler=None,
                bb_size=len(cfg),
                byte_size=funcbytes,
                CFG=cfg,
                ARCH=procname,
                LIB_NAME=None,
                OBF=False,
                bin_type=bitness,
                file_path=idb_path
            )
            # print(funcbytes)
            graph_dict[func_name] = tmp_func_struct
            # pic = deepcopy(cfg)

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    # Plot
    # nx.draw(pic, with_labels=True)
    # pyplot.savefig('./cfg_test.png', dpi=300, bbox_inches='tight')

    with open(output_path, 'wb') as f_out:
        pickle.dump(graph_dict, f_out)


if __name__ == '__main__':
    if not idaapi.get_plugin_options("graph"):
        print("[!] -Ograph option is missing")
        ida_pro.qexit(1)

    plugin_options = idaapi.get_plugin_options("graph").split(";")
    if len(plugin_options) != 3:
        print("[!] -Ograph:INPUT_JSON:IDB_PATH:OUTPUT_DIR")
        ida_pro.qexit(1)

    input_json = plugin_options[0]
    idb_path = plugin_options[1]
    output_dir = plugin_options[2]

    with open(input_json) as f_in:
        selected_functions = json.load(f_in)

    if idb_path not in selected_functions:
        print("[!] Error! IDB path (%s) not in %s" % (idb_path, input_json))
        ida_pro.qexit(1)

    fva_list = selected_functions[idb_path]
    print("[D] Found %d addresses" % len(fva_list))

    generate_cfg(idb_path, fva_list, output_dir)
    ida_pro.qexit(0)