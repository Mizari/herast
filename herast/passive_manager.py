from herast.schemes_storage import SchemesStorage
from herast.schemes.base_scheme import Scheme
from herast.tree.matcher import Matcher

from typing import Dict, Optional
from collections import defaultdict

import herast.idb_settings as idb_settings
import herast.herast_settings as herast_settings


__schemes_storages : Dict[str, SchemesStorage] = {}
__schemes : Dict[str, Scheme] = {}
__enabled_schemes = set()
__storage2schemes = defaultdict(list)
__scheme2storage = {}

def initialize():
	load_all_storages()
	enable_all_schemes()

def get_passive_matcher():
	matcher = Matcher()
	for s in get_passive_schemes():
		matcher.add_scheme(s)
	return matcher

def register_storage_scheme(scheme):
	if not isinstance(scheme, Scheme):
		return

	import inspect
	storage_path = inspect.stack()[1].filename
	__storage2schemes[storage_path].append(scheme.name)
	__scheme2storage[scheme.name] = storage_path

	__schemes[scheme.name] = scheme

def get_passive_schemes():
	return [s for s in __schemes.values() if s.name in __enabled_schemes]

def enable_scheme(scheme_name):
	if scheme_name not in __schemes:
		return
	__enabled_schemes.add(scheme_name)

def disable_scheme(scheme_name):
	if scheme_name not in __schemes:
		return
	__enabled_schemes.discard(scheme_name)

def update_storage_status(storage):
	globally = storage.path in herast_settings.get_herast_enabled()
	inidb = storage.path in idb_settings.get_enabled_idb()
	enabled = True
	if globally and inidb:
		status = "Enabled globally and in idb"
	elif globally:
		status = "Enabled globally"
	elif inidb:
		status = "Enabled in IDB"
	else:
		enabled = False
		status = "Disabled"
	storage.status_text = status
	storage.enabled = enabled

def load_all_storages():
	for folder in herast_settings.get_herast_folders():
		load_storage_folder(folder)
	for file in herast_settings.get_herast_files():
		load_storage_file(file)

	for storage in __schemes_storages.values():
		update_storage_status(storage)

def enable_all_schemes():
	for storage_path in herast_settings.get_herast_enabled():
		__update_storage_schemes(storage_path)
	for storage_path in idb_settings.get_enabled_idb():
		__update_storage_schemes(storage_path)

def load_storage_folder(folder_name: str) -> None:
	import glob
	for full_path in glob.iglob(folder_name + '/**/**.py', recursive=True):
		load_storage_file(full_path)

def load_storage_file(filename: str) -> bool:
	storage = SchemesStorage.from_file(filename)
	if storage is None:
		print("[!] WARNING: failed to load", filename, "storage")
		return False

	__schemes_storages[filename] = storage
	return True

def get_storages_folders():
	global_folders = herast_settings.get_herast_folders()
	idb_folders = idb_settings.get_idb_folders()
	return global_folders + idb_folders

def get_storage(filename: str) -> Optional[SchemesStorage]:
	return __schemes_storages.get(filename, None)

def get_storages():
	return [s for s in __schemes_storages.values()]

def get_enabled_storages():
	return [s for s in __schemes_storages.values() if s.enabled]

def __discard_storage_schemes(storage_path):
	for scheme_name in __storage2schemes.pop(storage_path, []):
		__enabled_schemes.discard(scheme_name)
		__schemes.pop(scheme_name, None)

def __update_storage_schemes(storage_path):
	if storage_path not in herast_settings.get_herast_enabled() and storage_path not in idb_settings.get_enabled_idb():
		return
	__enabled_schemes.update(__storage2schemes[storage_path])

def disable_storage_in_idb(storage_path):
	storage = get_storage(storage_path)
	if storage is None or not storage.enabled:
		return False

	idb_settings.remove_enabled_storage(storage_path)
	__discard_storage_schemes(storage)
	update_storage_status(storage)
	return True

def enable_storage_in_idb(storage_path):
	storage = get_storage(storage_path)
	if storage is None or storage.enabled or storage.error:
		return False

	idb_settings.add_enabled_storage(storage_path)
	__update_storage_schemes(storage_path)
	update_storage_status(storage)
	return True

def reload_storage(storage_path):
	storage = get_storage(storage_path)
	if storage is None:
		return False

	try:
		from .tree.utils import load_python_module_from_file
		new_module = load_python_module_from_file(storage_path)
	except Exception as e:
		new_module = None

	if new_module is None:
		import traceback
		storage.module = None
		storage.error = True
		storage.enabled = False
		storage.status_text = traceback.format_exc()
		return False

	storage.module = new_module
	update_storage_status(storage)
	return True