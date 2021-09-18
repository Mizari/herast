import idaapi

idaapi.require('tree.processing')
idaapi.require('tree.matcher')
idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.patterns.expressions')
idaapi.require('loader')
idaapi.require('views.patterns_manager_view')
idaapi.require('tree.consts')

from tree.processing import TreeProcessor
from tree.matcher import Matcher
from views.patterns_manager_view import ShowScriptManager
from loader import PatternStorageModel

import time

storage = PatternStorageModel()

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

# class ReloadScripts(idaapi.action_handler_t):
#     def __init__(self):
#         super(ReloadScripts, self).__init__()
#         self.name           = "ReloadScriptsAction"
#         self.description    = "Hot-reload of herast-scripts"
#         self.hotkey         = "Shift-R"
    
#     def activate(self, ctx):
#         global ldr
#         ldr.reload()
#         print("Scripts of herast has been reloaded!")

#     def update(self, ctx):
#         return idaapi.AST_ENABLE_ALWAYS

def herast_callback(*args):
    event = args[0]

    if event == idaapi.hxe_maturity:
        cfunc, level = args[1], args[2]
        if level == idaapi.CMAT_FINAL:
            try:
                m = Matcher(cfunc)

                global storage
                for p in storage.ready_patterns:
                    if p.enabled:
                        for exported_pattern, exported_handler in p.module.__exported:
                            m.insert_pattern(exported_pattern, exported_handler)

                tp = TreeProcessor.from_cfunc(cfunc, m, need_expression_traversal=False)
                
                traversal_start = time.time()

                tp.process_tree()

                traversal_end = time.time()
                print("[TIME] Tree traversal done within %f seconds" % (traversal_end - traversal_start))
            except Exception as e:
                print(e)
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
    # __register_action(ReloadScripts())

    if not idaapi.init_hexrays_plugin():
        print("Failed to initialize Hex-Rays SDK")
        return

    global storage
    action = ShowScriptManager(storage)
    idaapi.register_action(idaapi.action_desc_t(action.name, action.description, action, action.hotkey))  

    print('Hooking for HexRays events')
    idaapi.install_hexrays_callback(herast_callback)



if __name__ == '__main__':
    main()
