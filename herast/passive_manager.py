from __future__ import annotations
import os

from herast.schemes_storage import SchemesStorage
from herast.tree.scheme import Scheme
from herast.tree.matcher import Matcher

import herast.settings.settings_manager as settings_manager

__schemes_storages : dict[str, SchemesStorage] = {}
__schemes : dict[str, Scheme] = {}
from collections import defaultdict as __defaultdict
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
	new_storage = SchemesStorage(storage_path)
	__schemes_storages[storage_path] = new_storage
	if settings_manager.get_storage_status(storage_path) == "enabled":
		__load_storage(new_storage)
		enable_storage(storage_path)

	if rebuild_passive_matcher:
		__rebuild_passive_matcher()

def __unload_storage(storage: SchemesStorage) -> bool:
	if not storage.unload_module():
		return False

	__discard_storage_schemes(storage)
	return True

def __load_storage(storage: SchemesStorage) -> bool:
	rv = storage.load_module()
	if not rv:
		# in case exception happened somewhere in between
		# and something got added
		__discard_storage_schemes(storage)
	return rv

def __discard_storage_schemes(storage: SchemesStorage):
	for scheme in storage.get_schemes():
		__schemes.pop(scheme.name, None)
	storage.clear_schemes()



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
	storage = get_storage(storage_path)
	if storage is None:
		print("Internal error, failed to find storage when registering new scheme")
		return

	storage.add_scheme(scheme)

	__schemes[scheme.name] = scheme

def get_storage(filename: str) -> SchemesStorage|None:
	"""Get storage by its path."""
	return __schemes_storages.get(filename)

def get_storages() -> list[SchemesStorage]:
	"""Get all storages."""
	return [s for s in __schemes_storages.values()]

def get_storages_folders(in_idb=False, globally=False) -> list[str]:
	"""Get all storages folders.

	:param in_idb: get only IDB storages folders
	:param globally: get only global storages folders
	"""
	return settings_manager.get_storages_folders(in_idb=in_idb, globally=globally)

def get_storages_files_from_folder(folder:str ) -> list[str]:
	"""
	"""

	if folder not in settings_manager.get_storages_folders():
		print("No such folder in settings")
		return []

	storages_filenames = []
	for file_path in __find_python_files_in_folder(folder):
		if get_storage(file_path) is not None:
			storages_filenames.append(file_path)
	return storages_filenames

def is_storage_enabled(storage_path: str) -> bool:
	"""
	"""

	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	return storage.enabled

def get_enabled_storages() -> list[SchemesStorage]:
	"""Get only enabled storages."""
	return [s for s in __schemes_storages.values() if s.enabled]

def get_schemes():
	"""Get dict {scheme_name -> scheme)"""
	return dict(__schemes)


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
	for scheme in storage.get_schemes():
		__schemes.pop(scheme.name, None)

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
	for scheme in storage.get_schemes():
		__schemes[scheme.name] = scheme
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
	storage = get_storage(storage_path)
	if storage.is_loaded():
		__unload_storage(storage)
	del __schemes_storages[storage_path]
	return True

def reload_storage(storage_path: str) -> bool:
	"""Reload storage module."""
	storage = get_storage(storage_path)
	if storage is None:
		print("No such storage", storage_path)
		return False

	should_enable_later = storage.enabled

	if storage.is_loaded() and not __unload_storage(storage):
		print("Failed to unload storage in reloading", storage_path)
		return False

	if not __load_storage(storage):
		print("Failed to load storage on reloading", storage_path)
		return False

	if should_enable_later and not enable_storage(storage_path):
		print("Failed to reenable storage", storage_path, "but reloaded successfully")

	storage.status_text = __get_storage_status_text(storage_path)
	__rebuild_passive_matcher()
	return True