import idaapi
import idc

# [TODO]: resolving global objects to get their names or at least their addresses

def _resolve_obj_address(obj):
    if obj.op != idaapi.cot_obj:
        return None
    
    if obj.obj_ea != idaapi.BADADDR and obj.obj_ea is not None:
        return obj.obj_ea

    return None

def _resolve_obj_symbol(obj):
    ea = _resolve_obj_address(obj)
    if ea is None:
        return None

    return idaapi.get_name(ea)


def resolve_calling_function_from_node(call_node):
    node = call_node
    while node.x.op == idaapi.cot_cast:
        node = node.x

    if node.x.op == idaapi.cot_obj:
        return _resolve_obj_address(node.x), _resolve_obj_symbol(node.x)
    
    elif node.x.op == idaapi.cot_helper:
        return None, node.x.helper

    else:
        return None, None

def get_obj_from_call_node(call_node):
    node = call_node
    while node.x.op == idaapi.cot_cast:
        node = node.x

    if node.x.op == idaapi.cot_obj:
        return node.x

    return None

def resolve_name_address(name):
    return idc.get_name_ea_simple(name)


# [TODO]: remove instruction from ast completly by replacing parent-block with identical, but without unwanted instruction
def remove_instruction_from_ast(unwanted_ins, parent):
    assert type(unwanted_ins) is idaapi.cinsn_t, "Removing item must be an instruction (cinsn_t)"

    block = None
    if type(parent) is idaapi.cinsn_t and parent.op == idaapi.cit_block:
        block = parent

    elif type(parent) is idaapi.cfuncptr_t or type(parent) is idaapi.cfunc_t:
        ins = parent.body.find_parent_of(unwanted_ins).cinsn
        assert type(ins) is idaapi.cinsn_t and ins.op == idaapi.cit_block, "block is not cinsn_t or op != idaapi.cit_block"
        block = ins

    else:
        raise TypeError("Parent must be cfuncptr_t or cblock_t")

    # try:
    #     new_block = idaapi.cblock_t()
    #     for i in block.cblock:
    #         if i == unwanted_ins:
    #             continue
            
    #         new_block.push_back(i)
        
        
    #     # del new_block
    # except Exception as e:
    #     print(e)
    #     print(e)
    #     print(e)