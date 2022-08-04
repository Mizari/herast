import typing
import herast
from herast.settings.base_settings import BaseSettings

import herast.settings.idb_settings as idb_settings
import herast.settings.global_settings as global_settings
from herast.settings.idb_settings import settings_instance as __idb_settings
from herast.settings.global_settings import settings_instance as __global_settings

def reload_settings():
	"""Reloads plugin settings file and IDB setting nodes"""
	idb_settings.reload_settings()
	global_settings.reload_settings()
	global __idb_settings
	__idb_settings = idb_settings.settings_instance
	global __global_settings
	__global_settings = global_settings.settings_instance


# By default settings getters return global settings overwritten by idb settings

def get_storages_statuses(in_idb=False, globally=False) -> typing.Dict[str, str]:
	"""Get enabled/disabled statuses for selected storages.
	
	:param in_idb: get only IDB storages statuses
	:param globally: get only global storages statuses
	:return: dict storage_path -> storage_status
	"""
	if in_idb:
		return dict(__idb_settings.storages_statuses)
	if globally:
		return dict(__global_settings.storages_statuses)

	d = dict(__global_settings.storages_statuses)
	d.update(__idb_settings.storages_statuses)
	return d

def get_storage_status(storage_path: str, in_idb=False, globally=False) -> str:
	"""Get enabled/disabled status for specific storage

	:param in_idb: get only IDB storages status
	:param globally: get only global storages status
	"""
	d = get_storages_statuses(in_idb=in_idb, globally=globally)
	return d.get(storage_path, "disabled")

def get_storages_folders(in_idb=False, globally=False) -> typing.List[str]:
	"""Get a list of storages folders. 

	:param in_idb: get only IDB storages folders
	:param globally: get only global storages folders
	"""
	if in_idb:
		return list(__idb_settings.storages_folders)
	if globally:
		return list(__global_settings.storages_folders)

	return __idb_settings.storages_folders + __global_settings.storages_folders

def get_storages_files(in_idb=False, globally=False) -> typing.List[str]:
	"""Get a list of storages files. Does not include storages files found in storages folders.

	:param in_idb: get only IDB storages files
	:param globally: get only global storages files
	"""
	if in_idb:
		return list(__idb_settings.storages_files)
	if globally:
		return list(__global_settings.storages_files)

	return __global_settings.storages_files + __idb_settings.storages_files

def get_time_matching(in_idb=False, globally=False) -> bool:
	"""Get a bool whether herast should calculate time spent on matching.
	If both IDB and global settings are None, then False is returned.
	Otherwise IDB settings go first.
	
	:param in_idb: get only IDB time matching
	:param globally: get only global time matching
	"""
	if in_idb:
		if __idb_settings.time_matching is None:
			return False
		else:
			return __idb_settings.time_matching

	if globally:
		if __global_settings.time_matching is None:
			return False
		else:
			return __global_settings.time_matching

	rv = __idb_settings.time_matching
	if rv is not None:
		return rv

	if __global_settings.time_matching is not None:
		return __global_settings.time_matching
	else:
		return False


# By default settings changing api modify in IDB
# In order to modify globally one should use kwarg for it

def __get_settings(globally=False) -> BaseSettings:
	if globally:
		return __global_settings
	else:
		return __idb_settings

def enable_storage(storage_path: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.enable_storage(storage_path)

def disable_storage(storage_path: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.disable_storage(storage_path)

def enable_scheme(scheme_name: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.enable_scheme(scheme_name)

def disable_scheme(scheme_name:str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.disable_scheme(scheme_name)

def add_storage_folder(storages_folder: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.add_folder_storage(storages_folder)

def remove_storage_folder(storages_folder: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.remove_storage_folder(storages_folder)

def add_storage_file(storage_path: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.add_storage_file(storage_path)

def remove_storage_file(storage_path: str, globally=False):
	"""By default in IDB, given globally=True does globally only."""
	s = __get_settings(globally=globally)
	s.remove_file_storage(storage_path)