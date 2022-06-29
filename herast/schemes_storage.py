import os

from .tree.utils import load_python_module_from_file


class SchemesStorage:
	def __init__(self, path, module, enabled, error=False):
		self.path = path
		self.filename = os.path.basename(path)
		self.module = module
		self.enabled = enabled
		self.error = error
		self.status_text = None
		self.source = None

	@classmethod
	def from_file(cls, file_path):
		module = load_python_module_from_file(file_path)
		if module is None:
			return None

		return cls(file_path, module, False)

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