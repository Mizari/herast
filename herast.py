import time
import idaapi

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


class HerastPlugin(idaapi.plugin_t):
	flags = 0
	wanted_name = "herast"
	comment = ""
	help = ""
	wanted_hotkey = ""

	def herast_callback(self, *args):
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

	def init(self):
		if not idaapi.init_hexrays_plugin():
			return idaapi.PLUGIN_SKIP

		def __register_action(action):
			idaapi.register_action(
				idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
			)

		# first import before IDB got loaded does not correctly loads settings
		settings_manager.reload_settings()

		__register_action(smanager_view.ShowScriptManager())

		idaapi.remove_hexrays_callback(self.herast_callback)
		idaapi.install_hexrays_callback(self.herast_callback)

		passive_manager.initialize()
		action_manager.initialize()
		hx_callback_manager.initialize()
		return idaapi.PLUGIN_KEEP
	
	def run(self, arg):
		return

	def term(self):
		return

def PLUGIN_ENTRY():
	return HerastPlugin()

# if __name__ == '__plugins__herast':
if __name__ == "__main__":
	reload_modules()