import idaapi

from . import actions

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
        line_numbers = get_selected_lines(hx_view)
        return


actions.action_manager.register(PatternCreationHandler())