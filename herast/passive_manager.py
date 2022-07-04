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
	def find_python_files_in_folder(folder):
		import glob
		for file_path in glob.iglob(folder + '/**/**.py', recursive=True):
			yield file_path

	storages_files = settings_manager.get_storages_files()
	for folder in settings_manager.get_storages_folders():
		storages_files += find_python_files_in_folder(folder)

	for file_path in storages_files:
		if settings_manager.get_storage_status(file_path) == "enabled":
			storage = SchemesStorage.from_file(file_path)
			if storage is None:
				print("[!] WARNING: failed to load", file_path, "storage")
				storage = SchemesStorage(file_path, None, False, True)
				storage.status_text = "Failed to load"

			else:
				storage.status_text = __get_storage_status_text(file_path)
				storage.enabled = True
				__enabled_schemes.update(__storage2schemes[file_path])

		else:
			storage = SchemesStorage(file_path, None, False)
			storage.status_text = "Disabled"

		__schemes_storages[file_path] = storage

	__rebuild_passive_matcher()

def __rebuild_passive_matcher():
	global __passive_matcher
	__passive_matcher = Matcher()
	for s in __schemes.values():
		if s.name in __enabled_schemes:
			__passive_matcher.add_scheme(s)

def __get_storage_status_text(storage_path):
	globally = settings_manager.get_storage_status(storage_path, globally=True) == "enabled"
	in_idb = settings_manager.get_storage_status(storage_path, in_idb=True) == "enabled"
	if globally and in_idb:
		status = "Enabled globally and in IDB"
	elif globally:
		status = "Enabled globally"
	elif in_idb:
		status = "Enabled in IDB"
	else:
		status = "Disabled"
	return status

def __discard_storage_schemes(storage_path):
	for scheme_name in __storage2schemes.get(storage_path, []):
		__enabled_schemes.discard(scheme_name)
	__rebuild_passive_matcher()

def __update_storage_schemes(storage_path):
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
	__discard_storage_schemes(storage_path)
	storage.status_text = __get_storage_status_text(storage.path)
	return True

def enable_storage(storage_path):
	storage = get_storage(storage_path)
	if storage is None or storage.enabled or storage.error:
		return False

	storage.enabled = True
	settings_manager.enable_storage(storage_path)
	__update_storage_schemes(storage_path)
	storage.status_text = __get_storage_status_text(storage.path)
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