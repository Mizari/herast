import os
import traceback

from .tree.utils import load_python_module_from_file


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