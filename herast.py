import idaapi

idaapi.require('tree.processing')
idaapi.require('tree.matcher')
idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.patterns.expressions')
idaapi.require('graph.view')
idaapi.require('views.patterns_edit')
idaapi.require('loader')

from tree.processing import TreeProcessor
from tree.matcher import Matcher


idaapi.require('test_patterns.call_explore')
from test_patterns.call_explore import test_pattern, test_handler
# from test_patterns.collapse_exception_branch import test_pattern, test_handler

# from graph.view import CFuncGraphViewer
# from views.patterns_edit import PatternsManager
import time

ldr = loader.Loader(HerastConfig.LOAD_DIRECTORY)

class HerastConfig:

    LOAD_DIRECTORY = 'test_patterns'


def unload_callback():
    try:
        return idaapi.remove_hexrays_callback(herast_callback)
    except:
        pass

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

class ReloadScripts(idaapi.action_handler_t):
    def __init__(self):
        super(ReloadScripts, self).__init__()
        self.name           = "ReloadScriptsAction"
        self.description    = "Hot-reload of herast-scripts"
        self.hotkey         = "Shift-R"
    
    def activate(self, ctx):
        global ldr
        ldr.reload()
        print("Scripts of herast has been reloaded!")

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def herast_callback(*args):
    event = args[0]

    if event == idaapi.hxe_maturity:
        cfunc, level = args[1], args[2]
        if level == idaapi.CMAT_FINAL:
            try:
                pass
                # print("CALLED!")
                # m = Matcher(cfunc)
                # m.insert_pattern(test_pattern, test_handler)

                # tp = TreeProcessor.from_cfunc(cfunc, m, m.expressions_traversal_is_needed())
                
                # traversal_start = time.time()

                # tp.process_tree()

                # traversal_end = time.time()

                # print("[TIME] Traversal done within %f seconds" % (traversal_end - traversal_start))

                # test purposes, show graph
                # gv = CFuncGraphViewer("Huypizda")
                # gv.Show()

                # test purposes, show qt gui
                # pm = PatternsManager()
                # pm.Show()
            except Exception as e:
                raise e

    return 0


def __register_action(action):
        result = idaapi.register_action(
            idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
        )
        print("Registered %s with status(%x)" % (action.name, result))


def main():
    # dummy way to register action to unload hexrays-callback, thus it won't be triggered multiple times at once
    # 
    __register_action(UnloadCallbackAction())
    __register_action(ReloadScripts())

    if not idaapi.init_hexrays_plugin():
        print("Failed to initialize Hex-Rays SDK")
        return

    print('Hooking for HexRays events')
    idaapi.install_hexrays_callback(herast_callback)


if __name__ == '__main__':
    main()