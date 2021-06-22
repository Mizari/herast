import idaapi

idaapi.require('tree.processing')
idaapi.require('tree.matcher')
idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.patterns.expressions')
idaapi.require('graph.view')
idaapi.require('views.patterns_edit')

from tree.processing import TreeProcessor
from tree.matcher import Matcher

from tree.patterns.abstracts import AnyPat, SeqPat, OrPat
from tree.patterns.instructions import *
from tree.patterns.expressions import *

idaapi.require('test_patterns.call_explore')
from test_patterns.call_explore import test_pattern, test_handler

# from graph.view import CFuncGraphViewer
# from views.patterns_edit import PatternsManager
import time

# [NOTE]: Actual for 7.6
class HR_EVENT:
    HXE_FLOWCHART               = 0
    HXE_STKPNTS                 = 1
    HXE_PROLOG                  = 2
    HXE_MICROCODE               = 3
    HXE_PREOPTIMIZED            = 4
    HXE_LOCOPT                  = 5
    HXE_PREALLOC                = 6
    HXE_GLBOPT                  = 7
    HXE_STRUCTURAL              = 8
    HXE_MATURITY                = 9
    HXE_INTERR                  = 10
    HXE_COMBINE                 = 11
    HXE_PRINT_FUNC              = 12
    HXE_FUNC_PRINTED            = 13
    HXE_RESOLVE_STKADDRS        = 14
    HXE_OPEN_PSEUDOCODE         = 100
    HXE_SWITCH_PSEUDOCODE       = 101
    HXE_REFRESH_PSEUDOCODE      = 102
    HXE_CLOSE_PSEUDOCODE        = 103
    HXE_KEYBOARD                = 104
    HXE_RIGHT_CLICK             = 105
    HXE_DOUBLE_CLICK            = 106
    HXE_CURPOS                  = 107
    HXE_CREATE_HINT             = 108
    HXE_TEXT_READY              = 109
    HXE_POPULATING_POPUP        = 110
    LXE_LVAR_NAME_CHANGED       = 111
    LXE_LVAR_TYPE_CHANGED       = 112
    LXE_LVAR_CMT_CHANGED        = 113
    LXE_LVAR_MAPPING_CHANGED    = 114
    HXE_CMT_CHANGED             = 115

# [NOTE]: Actual for 7.6
class CMAT_LEVEL:
    ZERO    = 0
    BUILT   = 1
    TRANS1  = 2
    NICE    = 3
    TRANS2  = 4
    CPA     = 5
    TRANS3  = 6
    CASTED  = 7
    FINAL   = 8


class UnloadCallbackAction(idaapi.action_handler_t):
    def __init__(self):
        super(UnloadCallbackAction, self).__init__()
        self.name           = "UnloadCallbackAction"
        self.description    = "Unload herast HexRays-callback before loading script (development purpose only)"
        self.hotkey         = "Ctrl-Shift-E"
    
    def activate(self, ctx):
        print("Unloaded herast callback with status(%x)" % (unload_callback()))
        

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def herast_callback(*args):
    event = args[0]

    if event == idaapi.hxe_maturity:
        cfunc, level = args[1], args[2]
        if level == idaapi.CMAT_FINAL:
            try:
                print("CALLED!")
                m = Matcher(cfunc)
                m.insert_pattern(test_pattern, test_handler)
                tp = TreeProcessor(cfunc, m)
                
                traversal_start = time.time()

                tp.process_function()

                traversal_end = time.time()

                print("[TIME] Traversal done within %f seconds" % (traversal_end - traversal_start))

                # test purposes, show graph
                # gv = CFuncGraphViewer("Huypizda")
                # gv.Show()

                # test purposes, show qt gui
                # pm = PatternsManager()
                # pm.Show()
            except Exception as e:
                raise e

    return 0


def unload_callback():
    try:
        return idaapi.remove_hexrays_callback(herast_callback)
    except:
        pass

def register_unload_action(action):
        result = idaapi.register_action(
            idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
        )
        print("Registered UnloadCallbackAction with status(%x)" % result)


def main():
    # dummy way to register action to unload hexrays-callback, thus it won't be triggered multiple times at once
    # 
    register_unload_action(UnloadCallbackAction())


    if not idaapi.init_hexrays_plugin():
        print("Failed to initialize Hex-Rays SDK")
        return
    

    print('Hooking for HexRays events')
    idaapi.install_hexrays_callback(herast_callback)
    



if __name__ == '__main__':
    main()