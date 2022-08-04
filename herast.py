import time
import idaapi
import ida_hexrays

def reload_modules():
	# order of requires (from imported to importers) is most likely important
	idaapi.require('herast.settings.base_settings')
	idaapi.require('herast.settings.idb_settings')
	idaapi.require('herast.settings.global_settings')
	idaapi.require('herast.settings.settings_manager')
	idaapi.require('herast.tree.consts')
	idaapi.require('herast.tree.utils')
	idaapi.require('herast.tree.pattern_context')
	idaapi.require('herast.tree.processing')
	idaapi.require('herast.tree.patterns.base_pattern')
	idaapi.require('herast.tree.patterns.abstracts')
	idaapi.require('herast.tree.patterns.instructions')
	idaapi.require('herast.tree.patterns.expressions')
	idaapi.require('herast.tree.patterns.helpers')
	idaapi.require('herast.tree.matcher')
	idaapi.require('herast.tree.callbacks')
	idaapi.require('herast.tree.actions')
	idaapi.require('herast.tree.selection_factory')

	idaapi.require('herast.tree.scheme')
	idaapi.require('herast.schemes_storage')

	idaapi.require('herast.passive_manager')

	idaapi.require('herast.views.storage_manager_view')

	idaapi.require('herapi')


import herast.views.storage_manager_view as smanager_view
import herast.passive_manager as passive_manager
import herast.settings.settings_manager as settings_manager

from herast.tree.actions import action_manager, hx_callback_manager


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

	assert isinstance(cfunc.body, idaapi.cinsn_t), "Function body is not cinsn_t"
	assert isinstance(cfunc.body.cblock, idaapi.cblock_t), "Function body must be a cblock_t"

	try:
		matcher = passive_manager.get_passive_matcher()
		if settings_manager.get_time_matching():
			traversal_start = time.time()
			matcher.match_cfunc(cfunc)
			traversal_end = time.time()
			print("[TIME] Tree traversal done within %f seconds" % (traversal_end - traversal_start))
		else:
			matcher.match_cfunc(cfunc)

	except Exception as e:
		print(e)
		raise e

	return 0
herast_callback.__reload_helper = True


def __register_action(action):
		idaapi.register_action(
			idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
		)
		# print("Registered %s with status(%x)" % (action.name, result))


def main():
	if not idaapi.init_hexrays_plugin():
		return
	
	# first import before IDB got loaded does not correctly loads settings
	settings_manager.reload_settings()

	__register_action(smanager_view.ShowScriptManager())
	# dummy way to register action to unload hexrays-callback, thus it won't be triggered multiple times at once
	__register_action(UnloadCallbackAction())
	# __register_action(ReloadScripts())

	for cb in ida_hexrays.__cbhooks_t.instances:
		callback = cb.callback
		if callback.__dict__.get("__reload_helper", False):
			idaapi.remove_hexrays_callback(callback)

	idaapi.install_hexrays_callback(herast_callback)

	passive_manager.__initialize()
	action_manager.initialize()
	hx_callback_manager.initialize()


class NoPlugin(idaapi.plugin_t):
	flags = 0
	wanted_name = "skipped"

	def init(self):
		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		return

	def term(self):
		return

def PLUGIN_ENTRY():
	return NoPlugin()

main()
# if __name__ == '__plugins__herast':
if __name__ == "__main__":
	reload_modules()