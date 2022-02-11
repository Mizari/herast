import idaapi

from . import actions


def get_obj_ids(vdui, lnnum):
    obj_ids = []
    pc = vdui.cfunc.get_pseudocode()
    if lnnum >= len(pc):
        return obj_ids
    line = pc[lnnum].line
    tag = idaapi.COLOR_ON + chr(idaapi.COLOR_ADDR)
    pos = line.find(tag)
    while pos != -1 and len(line[pos+len(tag):]) >= idaapi.COLOR_ADDR_SIZE:
        addr = line[pos+len(tag):pos+len(tag)+idaapi.COLOR_ADDR_SIZE]
        idx = int(addr, 16)
        a = idaapi.ctree_anchor_t()
        a.value = idx
        if a.is_valid_anchor() and a.is_citem_anchor():
            item = vdui.cfunc.treeitems.at(a.get_index())
            if item:
                obj_ids.append(item.obj_id)
        pos = line.find(tag, pos+len(tag)+idaapi.COLOR_ADDR_SIZE)
    return obj_ids

# -----------------------------------------------------------------------
def get_selected_lines(vdui):
    vdui.get_current_item(idaapi.USE_KEYBOARD)
    line_numbers = []
    w = vdui.ct
    p0 = idaapi.twinpos_t()
    p1 = idaapi.twinpos_t()
    if idaapi.read_selection(w, p0, p1):
        place0 = p0.place(w)
        place1 = p1.place(w)
        a = place0.as_simpleline_place_t(place0).n
        b = place1.as_simpleline_place_t(place1).n
        line_numbers = [i for i in range(a, b+1)]
    else:
        line_numbers = [vdui.cpos.lnnum]
    return line_numbers

        

class PatternCreationHandler(actions.HexRaysPopupAction):
    description = "Create herast-pattern from selection"

    def __init__(self):
        super(actions.HexRaysPopupAction, self).__init__()
        self.selection_is_empty = True
    
    def check(self, hx_view):
        return True

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        print(dir(ctx))
        line_numbers = get_selected_lines(hx_view)
        print("Selected lines: %s" % (line_numbers))

        objs = list()

        for n in line_numbers:
            objs+= get_obj_ids(hx_view, n)

        unique_objs = set(objs)

        print("Object ids: %s" % unique_objs)
        return


actions.action_manager.register(PatternCreationHandler())