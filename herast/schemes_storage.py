from __future__ import annotations

import os
import sys
import traceback
import importlib
import importlib.util

from herast.tree.scheme import Scheme

def load_python_module_from_file(module_path:str):
	if not os.path.exists(module_path):
		print("[!] Trying to load non existing file", module_path)
		return None

	module_name = os.path.basename(module_path)
	module_folder = os.path.dirname(module_path)
	if module_folder not in sys.path:
		sys.path.append(module_folder)
	spec = importlib.util.spec_from_file_location(module_name, module_path, submodule_search_locations=[module_folder])
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
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
		self.schemes : dict[str, Scheme] = {}

	def add_scheme(self, name:str, scheme:Scheme):
		self.schemes[name] = scheme

	def clear_schemes(self):
		self.schemes.clear()

	def get_schemes(self):
		for n, s in self.schemes.items():
			yield n, s

	def is_loaded(self):
		return self.module is not None
	
	def unload_module(self):
		self.schemes.clear()
		self.source = None
		self.enabled = False
		self.module = None
		self.status_text = "Disabled"
		self.error = False

	def load_module(self):
		if self.is_loaded():
			print("[!] WARNING: loading module, that is not unloaded")
			self.module = None

		try:
			self.module = load_python_module_from_file(self.path)
			self.status_text = None
			self.error = False
			return True

		except Exception as e:
			print("[!] Exception happened during loading module from file %s: %s" % (self.path, e))
			self.status_text = traceback.format_exc()
			self.error = True
			self.schemes.clear()
			self.enabled = False
			self.module = None
			return False

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