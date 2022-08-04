import typing

from herast.schemes_storage import SchemesStorage
from herast.tree.scheme import Scheme
from herast.tree.matcher import Matcher

import herast.settings.settings_manager as settings_manager

__schemes_storages : typing.Dict[str, SchemesStorage] = {}
__schemes : typing.Dict[str, Scheme] = {}
__enabled_schemes : typing.Set[Scheme] = set()
from collections import defaultdict as __defaultdict
__storage2schemes : typing.Dict[str, typing.List[str]]= __defaultdict(list)
__scheme2storage = {}
__passive_matcher = Matcher()

def __find_python_files_in_folder(folder: str):
	import glob
	for file_path in glob.iglob(folder + '/**/**.py', recursive=True):
		yield file_path

def __initialize():

	storages_files = settings_manager.get_storages_files()
	for folder in settings_manager.get_storages_folders():
		storages_files += __find_python_files_in_folder(folder)

	for file_path in storages_files:
		load_storage(file_path, rebuild_passive=False)

	__rebuild_passive_matcher()

def __rebuild_passive_matcher():
	global __passive_matcher
	__passive_matcher.schemes.clear()
	for s in __schemes.values():
		if s.name in __enabled_schemes:
			__passive_matcher.add_scheme(s)

def __get_storage_status_text(storage_path: str) -> str:
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

def __discard_storage_schemes(storage_path: str):
	for scheme_name in __storage2schemes.get(storage_path, []):
		__enabled_schemes.discard(scheme_name)
	__rebuild_passive_matcher()

def __update_storage_schemes(storage_path: str):
	__enabled_schemes.update(__storage2schemes[storage_path])
	__rebuild_passive_matcher()

def get_passive_matcher() -> Matcher:
	"""Get matcher, that automatically matches in every decompilation."""
	return __passive_matcher

def register_storage_scheme(scheme: Scheme):
	"""API for storages to export their schemes."""
	import inspect
	storage_path = inspect.stack()[1].filename
	__storage2schemes[storage_path].append(scheme.name)
	__scheme2storage[scheme.name] = storage_path

	__schemes[scheme.name] = scheme

def get_storage(filename: str) -> typing.Optional[SchemesStorage]:
	"""Get storage by its path."""
	return __schemes_storages.get(filename)

def get_storages() -> typing.List[SchemesStorage]:
	"""Get all storages."""
	return [s for s in __schemes_storages.values()]

def get_storages_folders(in_idb=False, globally=False) -> typing.List[str]:
	"""Get all storages folders.

	:param in_idb: get only IDB storages folders
	:param globally: get only global storages folders
	"""
	return settings_manager.get_storages_folders(in_idb=in_idb, globally=globally)

def get_enabled_storages() -> typing.List[SchemesStorage]:
	"""Get only enabled storages."""
	return [s for s in __schemes_storages.values() if s.enabled]

def enable_scheme(scheme_name: str):
	"""Change status of scheme to activate it in passive matching."""
	if scheme_name in __enabled_schemes:
		return
	__enabled_schemes.add(scheme_name)
	settings_manager.enable_scheme(scheme_name)

	if scheme_name not in __schemes:
		return
	__rebuild_passive_matcher()

def disable_scheme(scheme_name: str):
	"""Change status of scheme to deactivate it in passive matching."""
	if scheme_name not in __enabled_schemes:
		return
	__enabled_schemes.discard(scheme_name)
	settings_manager.disable_scheme(scheme_name)

	if scheme_name not in __schemes:
		return
	__rebuild_passive_matcher()

def disable_storage(storage_path: str) -> bool:
	"""Change status of a storage to not export schemes to passive matcher."""
	storage = get_storage(storage_path)
	if storage is None or not storage.enabled:
		return False

	storage.enabled = False
	settings_manager.disable_storage(storage_path)
	__discard_storage_schemes(storage_path)
	storage.status_text = __get_storage_status_text(storage.path)
	return True

def enable_storage(storage_path: str) -> bool:
	"""Change status of a storage to export schemes to passive matcher."""
	storage = get_storage(storage_path)
	if storage is None or storage.enabled or storage.error:
		return False

	if storage.module is None:
		if storage.load_module():
			__enabled_schemes.update(__storage2schemes[storage.path])
		else:
			return False

	storage.enabled = True
	settings_manager.enable_storage(storage_path)
	__update_storage_schemes(storage_path)
	storage.status_text = __get_storage_status_text(storage.path)
	return True

def add_storage_folder(storages_folder: str, global_settings=False):
	"""Add new storages from folder and rebuild passive matcher."""
	if storages_folder in settings_manager.get_storages_folders(globally=global_settings):
		return
	settings_manager.add_storage_folder(storages_folder, globally=global_settings)

	storages_files = __find_python_files_in_folder(storages_folder)
	for file_path in storages_files:
		load_storage(file_path, rebuild_passive=False)
	__rebuild_passive_matcher()

def remove_storage_folder(storages_folder: str, global_settings=False):
	"""Remove existing storages from folder and rebuild passive matcher."""
	if storages_folder not in settings_manager.get_storages_folders(globally=global_settings):
		return
	settings_manager.remove_storage_folder(storages_folder, global_settings)

	storages_files = __find_python_files_in_folder(storages_folder)
	for file_path in storages_files:
		unload_storage(file_path, rebuild_passive=False)
	__rebuild_passive_matcher()

def add_storage_file(storage_path: str, global_settings=False):
	"""Add new storage and rebuild passive matcher."""
	if storage_path in settings_manager.get_storages_files(globally=global_settings):
		return
	settings_manager.add_storage_file(storage_path, global_settings)
	load_storage(storage_path)

def remove_storage_file(storage_path: str, global_settings=False):
	"""Remove existing storage and rebuild passive matcher."""
	if storage_path in settings_manager.get_storages_files(globally=global_settings):
		return
	settings_manager.add_storage_file(storage_path, global_settings)
	unload_storage(storage_path)

def load_storage(storage_path: str, rebuild_passive=True) -> bool:
	"""Load new storage, that will not be saved in settings and rebuild passive matcher."""
	if get_storage(storage_path) is not None:
		return False

	if settings_manager.get_storage_status(storage_path) == "enabled":
		storage = SchemesStorage.from_file(storage_path)
		if storage is None:
			print("[!] WARNING: failed to load", storage_path, "storage")
			storage = SchemesStorage(storage_path, None, False, True)
			storage.status_text = "Failed to load"
			return False

		else:
			storage.status_text = __get_storage_status_text(storage_path)
			storage.enabled = True
			__enabled_schemes.update(__storage2schemes[storage_path])

	else:
		storage = SchemesStorage(storage_path, None, False)
		storage.status_text = "Disabled"

	__schemes_storages[storage_path] = storage
	if rebuild_passive:
		__rebuild_passive_matcher()
	return True

def unload_storage(storage_path: str, rebuild_passive=True):
	"""Remove existing storage, that will not be saved in settings and rebuild passive matcher."""
	storage = get_storage(storage_path)
	if storage is None:
		return False

	if storage.module is None:
		return True

	storage.unload_module()
	del __schemes_storages[storage_path]
	for scheme_name in __storage2schemes[storage_path]:
		del __schemes[scheme_name]
		__enabled_schemes.discard(scheme_name)
		del __scheme2storage[scheme_name]
	del __storage2schemes[storage_path]
	if rebuild_passive:
		__rebuild_passive_matcher()
	return True

def reload_storage(storage_path: str, rebuild_passive=True) -> bool:
	"""Reload storage and rebuild passive matcher."""
	storage = get_storage(storage_path)
	if storage is None:
		return False

	unload_storage(storage_path, rebuild_passive=False)
	if load_storage(storage_path, rebuild_passive=False):
		if rebuild_passive:
			__rebuild_passive_matcher()
		return True
	else:
		return False