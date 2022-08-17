import typing
import os

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
	storage_files = set(settings_manager.get_storages_files())
	for folder in settings_manager.get_storages_folders():
		storage_files.update(__find_python_files_in_folder(folder))

	for storage_path in storage_files:
		__add_storage_file(storage_path, rebuild_passive_matcher=False)

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

def __add_storages_folder(storages_folder_path: str, rebuild_passive_matcher=True):
	for file_path in __find_python_files_in_folder(storages_folder_path):
		__add_storage_file(file_path, rebuild_passive_matcher=False)

	if rebuild_passive_matcher:
		__rebuild_passive_matcher()

def __add_storage_file(storage_path: str, rebuild_passive_matcher=True):
	__schemes_storages[storage_path] = SchemesStorage(storage_path)
	if settings_manager.get_storage_status(storage_path) == "enabled":
		load_storage(storage_path)
		enable_storage(storage_path)

	if rebuild_passive_matcher:
		__rebuild_passive_matcher()




"""PUBLIC API"""

def get_passive_matcher() -> Matcher:
	"""Get matcher, that automatically matches in every decompilation."""
	return __passive_matcher

def register_storage_scheme(scheme: Scheme):
	"""API for storages to export their schemes."""

	if scheme.name in __schemes:
		print(scheme.name, "scheme already exists, skipping")
		return

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

def get_schemes():
	"""Get dict {scheme_name -> scheme)"""
	return dict(__schemes)

def enable_scheme(scheme_name: str) -> bool:
	"""Change status of scheme to activate it in passive matching."""

	if scheme_name not in __schemes:
		print("No such scheme", scheme_name)
		return False

	if scheme_name in __enabled_schemes:
		print(scheme_name, "is already enabled")
		return False

	__enabled_schemes.add(scheme_name)
	settings_manager.enable_scheme(scheme_name)

	__rebuild_passive_matcher()
	return True

def disable_scheme(scheme_name: str) -> bool:
	"""Change status of scheme to deactivate it in passive matching."""
	if scheme_name not in __schemes:
		print("No such scheme", scheme_name)
		return False

	if scheme_name not in __enabled_schemes:
		print(scheme_name, "is not yet enabled")
		return False

	__enabled_schemes.discard(scheme_name)
	settings_manager.disable_scheme(scheme_name)

	__rebuild_passive_matcher()
	return True

def disable_storage(storage_path: str) -> bool:
	"""Change status of a storage to not export schemes to passive matcher."""
	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	if not storage.enabled:
		print(storage_path, "is already disabled")
		return False

	storage.enabled = False
	settings_manager.disable_storage(storage_path)

	for scheme_name in __storage2schemes[storage_path]:
		__enabled_schemes.discard(scheme_name)
	storage.status_text = __get_storage_status_text(storage.path)
	__rebuild_passive_matcher()
	return True

def enable_storage(storage_path: str) -> bool:
	"""Change status of a storage to export schemes to passive matcher."""
	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	if storage.enabled:
		print(storage_path, "is already enabled")
		return False

	if storage.error:
		print(storage_path, "is errored, reload first")
		return False

	if not storage.is_loaded() and not storage.load_module():
		print("Failed to load module while enabling", storage_path)
		return False

	storage.enabled = True
	settings_manager.enable_storage(storage_path)
	__enabled_schemes.update(__storage2schemes[storage_path])
	__rebuild_passive_matcher()

	storage.status_text = __get_storage_status_text(storage.path)
	return True

def add_storage_folder(storages_folder: str, global_settings=False) -> bool:
	"""Add new storages from folder."""

	if storages_folder in settings_manager.get_storages_folders(globally=global_settings):
		print("Already have this folder", storages_folder)
		return False

	if not os.path.exists(storages_folder):
		print("No such folder exists", storages_folder)
		return False

	if not os.path.isdir(storages_folder):
		print(storages_folder, "is not a directory")
		return False

	settings_manager.add_storage_folder(storages_folder, globally=global_settings)
	__add_storages_folder(storages_folder)
	return True

def remove_storage_folder(storages_folder: str, global_settings=False) -> bool:
	"""Remove existing storages from folder."""

	if storages_folder not in settings_manager.get_storages_folders(globally=global_settings):
		print("No such folder", storages_folder)
		return False

	settings_manager.remove_storage_folder(storages_folder, global_settings)

	storages_files = __find_python_files_in_folder(storages_folder)
	for file_path in storages_files:
		if file_path in __schemes_storages:
			remove_storage_file(file_path)
	__rebuild_passive_matcher()
	return True

def add_storage_file(storage_path: str, global_settings=False) -> bool:
	"""Add new storage."""

	if storage_path in settings_manager.get_storages_files(globally=global_settings):
		print("Already have this storage file", storage_path)
		return False

	if not os.path.exists(storage_path):
		print("No such file exists", storage_path)
		return False

	if not os.path.isfile(storage_path):
		print(storage_path, "is not a file")
		return False

	settings_manager.add_storage_file(storage_path, global_settings)
	__add_storage_file(storage_path)
	return True

def remove_storage_file(storage_path: str, global_settings=False) -> bool:
	"""Remove existing storage."""

	if storage_path not in settings_manager.get_storages_files(globally=global_settings):
		print("No such storage file", storage_path)
		return False

	settings_manager.remove_storage_file(storage_path, global_settings)
	unload_storage(storage_path)
	return True

def load_storage(storage_path: str) -> bool:
	"""Load storage module."""

	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	if storage.is_loaded():
		print("Storage is already loaded", storage_path)
		return False

	if not storage.load_module():
		print("Failed to load storage", storage_path)
		return False

	return True

def unload_storage(storage_path: str) -> bool:
	"""Unload storage module."""
	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	if not storage.is_loaded():
		print("Storage is already unloaded", storage_path)
		return True

	if storage.enabled and not disable_storage(storage_path):
		print("Failed to disable storage before unloading", storage_path)
		return False

	if not storage.unload_module():
		print("Failed to unload storage", storage_path)
		return False

	for scheme_name in __storage2schemes[storage_path]:
		del __scheme2storage[scheme_name]
	del __storage2schemes[storage_path]

	return True

def reload_storage(storage_path: str) -> bool:
	"""Reload storage module."""
	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	should_enable_later = False
	if storage.enabled:
		should_enable_later = True
		disable_storage(storage_path)

	if storage.is_loaded():
		storage.unload_module()

	for scheme_name in __storage2schemes.pop(storage_path, []):
		del __scheme2storage[scheme_name]
		del __schemes[scheme_name]

	if not load_storage(storage_path):
		print("Failed to load storage on reloading", storage_path)
		return False

	if should_enable_later and not enable_storage(storage_path):
		print("Failed to reenable storage", storage_path, "but reloaded successfully")

	storage.status_text = __get_storage_status_text(storage_path)
	__rebuild_passive_matcher()
	return True