import time
import idaapi
import ida_hexrays

# order of requires (from imported to importers) is most likely important
idaapi.require('herast.tree.consts')
idaapi.require('herast.tree.utils')
idaapi.require('herast.tree.pattern_context')
idaapi.require('herast.tree.processing')
idaapi.require('herast.tree.patterns.abstracts')
idaapi.require('herast.tree.patterns.instructions')
idaapi.require('herast.tree.patterns.expressions')
idaapi.require('herast.tree.matcher')
idaapi.require('herast.tree.callbacks')
idaapi.require('herast.tree.actions')
idaapi.require('herast.tree.selection_factory')

idaapi.require('herast.schemes.base_scheme')
idaapi.require('herast.schemes.multi_pattern_schemes')
idaapi.require('herast.schemes.single_pattern_schemes')

idaapi.require('herast.storage_manager')

idaapi.require('herast.scheme_manager')

idaapi.require('herast.views.storage_manager_view')


from herast.tree.processing import TreeProcessor
from herast.tree.matcher import Matcher
from herast.views.storage_manager_view import ShowScriptManager
import herast.storage_manager as storage_manager
import herast.scheme_manager as scheme_manager

from herast.tree.actions import action_manager, hx_callback_manager
from herast.tree.selection_factory import PatternCreationHandler


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
	if event != idaapi.hxe_maturity:
		return 0

	cfunc, level = args[1], args[2]
	if level != idaapi.CMAT_FINAL:
		return 0

	try:
		assert isinstance(cfunc.body, idaapi.cinsn_t), "Function body is not cinsn_t"
		assert isinstance(cfunc.body.cblock, idaapi.cblock_t), "Function body must be a cblock_t"
		tp = TreeProcessor(cfunc)

		matcher = Matcher()
		for s in scheme_manager.get_enabled_schemes():
			matcher.add_scheme(s)

		def processing_callback(tree_proc, item):
			return matcher.check_schemes(tree_proc, item)

		traversal_start = time.time()

		if matcher.expressions_traversal_is_needed():
			tp.process_all_items(cfunc.body, processing_callback)
		else:
			tp.process_all_instrs(cfunc.body, processing_callback)

		traversal_end = time.time()
		print("[TIME] Tree traversal done within %f seconds" % (traversal_end - traversal_start))
	except Exception as e:
		print(e)
		raise e

	return 0
herast_callback.__reload_helper = True


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

	action = ShowScriptManager()
	idaapi.register_action(idaapi.action_desc_t(action.name, action.description, action, action.hotkey))  

	for cb in ida_hexrays.__cbhooks_t.instances:
		callback = cb.callback
		if callback.__dict__.get("__reload_helper", False):
			idaapi.remove_hexrays_callback(callback)

	print('Hooking for HexRays events')
	idaapi.install_hexrays_callback(herast_callback)

	storage_manager.load_all_storages()
	action_manager.initialize()
	hx_callback_manager.initialize()


main()
# if __name__ == '__plugins__herast':