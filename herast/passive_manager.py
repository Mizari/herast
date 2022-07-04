from __future__ import annotations as __annotiations

from herast.schemes_storage import SchemesStorage
from herast.schemes.base_scheme import Scheme
from herast.tree.matcher import Matcher

import herast.settings.settings_manager as settings_manager

__schemes_storages : dict[str, SchemesStorage] = {}
__schemes : dict[str, Scheme] = {}
__enabled_schemes = set()
from collections import defaultdict as __defaultdict
__storage2schemes = __defaultdict(list)
__scheme2storage = {}
__passive_matcher = Matcher()


def __initialize():
	for folder in settings_manager.get_storages_folders():
		__load_storage_folder(folder)
	for file in settings_manager.get_storages_files():
		__load_storage_file(file)

	for storage in __schemes_storages.values():
		storage.status_text = __get_storage_status_text(storage.path)
		if settings_manager.get_storage_status(storage.path) == "enabled":
			storage.enabled = True

	for storage_path in settings_manager.get_storages_statuses(globally=True):
		__update_storage_schemes(storage_path)
	for storage_path in settings_manager.get_storages_statuses():
		__update_storage_schemes(storage_path)

	__rebuild_passive_matcher()

def __rebuild_passive_matcher():
	global __passive_matcher
	__passive_matcher = Matcher()
	for s in __schemes.values():
		if s.name in __enabled_schemes:
			__passive_matcher.add_scheme(s)

def __get_storage_status_text(storage):
	globally = storage.path in settings_manager.get_storages_statuses(globally=True)
	inidb = storage.path in settings_manager.get_storages_statuses()
	if globally and inidb:
		status = "Enabled globally and in IDB"
	elif globally:
		status = "Enabled globally"
	elif inidb:
		status = "Enabled in IDB"
	else:
		status = "Disabled"
	return status

def __load_storage_folder(folder_name: str) -> None:
	import glob
	for full_path in glob.iglob(folder_name + '/**/**.py', recursive=True):
		__load_storage_file(full_path)

def __load_storage_file(filename: str) -> bool:
	storage = SchemesStorage.from_file(filename)
	if storage is None:
		print("[!] WARNING: failed to load", filename, "storage")
		return False

	__schemes_storages[filename] = storage
	return True

def __discard_storage_schemes(storage_path):
	for scheme_name in __storage2schemes.pop(storage_path, []):
		__enabled_schemes.discard(scheme_name)
		__schemes.pop(scheme_name, None)
	__rebuild_passive_matcher()

def __update_storage_schemes(storage_path):
	if storage_path not in settings_manager.get_storages_statuses(globally=True) and storage_path not in settings_manager.get_storages_statuses():
		return
	__enabled_schemes.update(__storage2schemes[storage_path])
	__rebuild_passive_matcher()

def get_passive_matcher():
	return __passive_matcher

def register_storage_scheme(scheme):
	if not isinstance(scheme, Scheme):
		return

	import inspect
	storage_path = inspect.stack()[1].filename
	__storage2schemes[storage_path].append(scheme.name)
	__scheme2storage[scheme.name] = storage_path

	__schemes[scheme.name] = scheme

def get_storages_folders():
	global_folders = settings_manager.get_storages_folders(globally=True)
	idb_folders = settings_manager.get_storages_folders()
	return global_folders + idb_folders

def get_storage(filename: str) -> SchemesStorage:
	return __schemes_storages.get(filename)

def get_storages():
	return [s for s in __schemes_storages.values()]

def get_enabled_storages():
	return [s for s in __schemes_storages.values() if s.enabled]

def enable_scheme(scheme_name):
	if scheme_name not in __schemes:
		return
	__enabled_schemes.add(scheme_name)
	__rebuild_passive_matcher()

def disable_scheme(scheme_name):
	if scheme_name not in __schemes:
		return
	__enabled_schemes.discard(scheme_name)
	__rebuild_passive_matcher()

def disable_storage(storage_path):
	storage = get_storage(storage_path)
	if storage is None or not storage.enabled:
		return False

	storage.enabled = False
	settings_manager.disable_storage(storage_path)
	__discard_storage_schemes(storage)
	storage.status_text = __get_storage_status_text(storage)
	return True

def enable_storage(storage_path):
	storage = get_storage(storage_path)
	if storage is None or storage.enabled or storage.error:
		return False

	storage.enabled = True
	settings_manager.enable_storage(storage_path)
	__update_storage_schemes(storage_path)
	storage.status_text = __get_storage_status_text(storage)
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
	storage.status_text = __get_storage_status_text(storage)
	__rebuild_passive_matcher()
	return True