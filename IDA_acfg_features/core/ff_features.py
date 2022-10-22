import idautils
import idc
import ida_idaapi


def get_func_incoming_calls(fva):
    """
    Get the xref to the current function.

    Args:
        fva: function virtual address

    Return:
        the number of xrefs
    """
    x_ref_list = [x for x in idautils.XrefsTo(fva) if x.iscode]
    return len(x_ref_list)


def get_size_local_vars(fva):
    """
    Get the dimension (size) of local variables.

    Args:
        fva: function virtual address

    Return:
        the size of local variables
    """
    # return idc.GetFrameLvarSize(fva)
    __EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
    if __EA64__:
        attr = 32
    else:
        attr = 20
    return idc.get_func_attr(fva, attr)

def f_sum(bbs_dict, key_f):
    """
    Return the sum for "key_f" values in bbs_dict.

    Args:
        bbs_dict: a dictionary with BBs features
        key_f: the name of the feature to sum in each BB

    Return:
        the sum of the selected feature
    """
    return sum([bbs_dict[bb_va][key_f] for bb_va in bbs_dict])


def get_function_features(fva, bbs_dict, len_edges):
    """
    Construction the dictionary with function-level features.

    Args:
        fva: function virtual address
        bbs_dict: a dictionary with all the features, one per BB
        len_eges: number of edges

    Return:
        a dictionary with function-level features
    """
    f_dict = {
        'n_func_calls': f_sum(bbs_dict, 'n_call_instrs'),
        'n_logic_instrs': f_sum(bbs_dict, 'n_logic_instrs'),
        'n_redirections': f_sum(bbs_dict, 'n_redirect_instrs'),
        'n_transfer_instrs': f_sum(bbs_dict, 'n_transfer_instrs'),
        'size_local_variables': get_size_local_vars(fva),
        'n_bb': len(bbs_dict),
        'n_edges': len_edges,
        'n_incoming_calls': get_func_incoming_calls(fva),
        'n_instructions': f_sum(bbs_dict, 'n_instructions')
    }
    return f_dict
