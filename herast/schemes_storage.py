import os
import traceback

import herast.idb_settings as idb_settings
from .tree.utils import load_python_module_from_file


def load_storage_module_from_file(path):
	module = load_python_module_from_file(path)
	if module is None:
		return None

	if not hasattr(module, "__exported"):
		return None
	return module



class SchemesStorage:
	def __init__(self, path, module, enabled, error=False):
		self.path = path
		self.filename = os.path.basename(path)
		self.module = module
		self.enabled = enabled
		self.error = error
		self.status_text = None
		self.source = None

	def get_status(self):
		if self.status_text is not None:
			return self.status_text

		if self.enabled:
			return "Enabled!"
		else:
			return "Disabled!"

	def get_source(self):
		if self.source is not None:
			return self.source

		if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
			with open(self.path, 'r') as f:
				self.source = f.read()
		return self.source

	def enable(self):
		if self.enabled:
			return

		if not self.error:
			if self.module is None:
				assert self.reload()
			if not self.error:
				stored_enabled_array = idb_settings.get_enabled_idb_storages()
				stored_enabled_array.append(self.path)
				idb_settings.save_enabled_idb_storages(stored_enabled_array)
				self.enabled = True

	def disable(self):
		if not self.enabled:
			return

		stored_enabled_array = idb_settings.get_enabled_idb_storages()
		if self.path in stored_enabled_array:
			stored_enabled_array.remove(self.path)
		idb_settings.save_enabled_idb_storages(stored_enabled_array)
		self.enabled = False

	def reload(self):
		if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
			try:
				del self.module
				self.module = load_storage_module_from_file(self.path)
				self.error = False
			except Exception as e:
				self.module = None
				self.error = True
				self.enabled = False
				self.status_text = traceback.format_exc()

			return True
		else:
			return False