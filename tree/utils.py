import idaapi


# [TODO]: resolving global objects to get their names or at least their addresses

def resolve_obj_address(obj):
    if obj.op != idaapi.cot_obj:
        return None
    
    if obj.obj_ea != idaapi.BADADDR and obj.obj_ea is not None:
        return obj.obj_ea

    raise NotImplementedError("Other methods of resolving address of cot_obj not yet implemented")


def resolve_obj_symbol(obj):
    ea = resolve_obj_address(obj)
    if ea is None:
        return None
    
    return idaapi.get_name(ea)


def get_obj_from_call_node(call_node):
    if call_node.x.op == idaapi.cot_cast:
        if call_node.x.x.op == idaapi.cot_obj:
            return call_node.x.x
    elif call_node.x.op == idaapi.cot_obj:
        return call_node.x

    raise NotImplementedError("This is not simple (cot_call)->(cot_cast)->(cot_obj) and this case handling not yet implemented")
    