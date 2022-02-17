import os
import glob
import traceback
import json

from .tree.utils import save_long_str_to_idb
from .tree.utils import load_long_str_from_idb
from .tree.utils import load_python_module_from_file

from typing import Dict, Optional


def load_storage_module_from_file(path):
	module = load_python_module_from_file(path)
	if not hasattr(module, "__exported"):
		return None
	return module

ARRAY_NAME = "$herast:PatternStorage"
def get_enabled_idb_storages():
	stored_string = load_long_str_from_idb(ARRAY_NAME) or '[]'
	stored_enabled_array = json.loads(stored_string)
	return stored_enabled_array

def save_enabled_idb_storages(stored_enabled_array):
	save_long_str_to_idb(ARRAY_NAME, json.dumps(stored_enabled_array))

class SchemesStorage:
	def __init__(self, path, module, enabled, error=False, log="Enabled!"):
		self.path = path
		self.filename = os.path.basename(path)
		self.module = module
		self.enabled = enabled
		self.error = error
		self.log = log
		self.source = str()

		if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
			with open(self.path, 'r') as f:
				self.source = f.read()

	def enable(self):
		if self.enabled:
			return

		if not self.error:
			self.log = "Enabled!"
			if self.module is None:
				assert self.reload()
			if not self.error:
				stored_enabled_array = get_enabled_idb_storages()
				stored_enabled_array.append(self.path)
				save_enabled_idb_storages(stored_enabled_array)
				self.enabled = True

	def disable(self):
		if not self.enabled:
			return

		stored_enabled_array = get_enabled_idb_storages()
		if self.path in stored_enabled_array:
			stored_enabled_array.remove(self.path)
		save_enabled_idb_storages(stored_enabled_array)
		self.enabled = False
		if not self.error:
			self.log = "Disabled!"

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
				self.log = traceback.format_exc()
			
			with open(self.path, 'r') as f:
				self.source = f.read()

			return True
		else:
			return False

schemes_storages : Dict[SchemesStorage] = {}

storages_folders = set()
default_storage_dir = os.path.dirname(__file__) + "\\ready_patterns\\"
if os.path.exists(default_storage_dir):
	storages_folders.add(default_storage_dir)
storages_files = set()

def load_all_storages():
	for folder in storages_folders:
		load_storage_folder(folder)
	for file in storages_files:
		load_storage_file(file)

def load_storage_folder(folder_name: str) -> None:
	for full_path in glob.iglob(folder_name + '/**/**.py', recursive=True):
		load_storage_file(full_path)

def load_storage_file(filename: str) -> bool:
	module = load_storage_module_from_file(filename)
	if module is None:
		return False

	is_enabled = filename in get_enabled_idb_storages()
	storage = SchemesStorage(filename, module, is_enabled)
	schemes_storages[filename] = storage
	return True

def get_storage(filename: str) -> Optional[SchemesStorage]:
	return schemes_storages.get(filename, None)

def get_enabled_storages():
	return [s for s in schemes_storages.values() if s.enabled]