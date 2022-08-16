import os
import sys
import traceback
import importlib
import importlib.util

def load_python_module_from_file(module_path:str):
	if not os.path.exists(module_path):
		print("[!] Trying to load non existing file", module_path)
		return None

	module_name = os.path.basename(module_path)
	module_folder = os.path.dirname(module_path)
	if module_folder not in sys.path:
		sys.path.append(module_folder)
	try:
		spec = importlib.util.spec_from_file_location(module_name, module_path, submodule_search_locations=[module_folder])
		module = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(module)
	except Exception as e:
		print("[!] Exception happened during loading module from file %s: %s" % (module_path, e))
		return None
	return module



class SchemesStorage:
	def __init__(self, path, module=None, enabled=False, error=False):
		self.path = path
		self.filename = os.path.basename(path)
		self.module = module
		self.enabled = enabled
		self.error = error
		self.status_text = None
		self.source = None

	def is_loaded(self):
		return self.module is not None
	
	def unload_module(self):
		self.source = None
		self.enabled = False
		self.module = None
		self.status_text = "Disabled"
		self.error = False

	def load_module(self):
		self.module = load_python_module_from_file(self.path)
		if self.module is None:
			self.status_text = traceback.format_exc()
			self.error = True
			self.enabled = False
			self.module = None
			return False

		else:
			self.status_text = None
			self.error = False
			return True

	@classmethod
	def from_file(cls, file_path):
		module = load_python_module_from_file(file_path)
		if module is None:
			return None

		return cls(file_path, module)

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