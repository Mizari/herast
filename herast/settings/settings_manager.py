from idb_settings import settings_instance as __idb_settings
from herast.settings.global_settings import settings_instance as __global_settings

def __get_settings(global_settings=False):
	if global_settings:
		return __global_settings
	else:
		return __idb_settings


def get_enabled_storages(global_settings=False):
	s = __get_settings(global_settings=global_settings)
	return list(s.enabled_storages)

def get_storages_folders(global_settings=False):
	s = __get_settings(global_settings=global_settings)
	return list(s.storages_folders)

def get_storages_files(global_settings=False):
	s = __get_settings(global_settings=global_settings)
	return list(s.storages_files)


def enable_storage(storage_path, global_settings=False):
	s = __get_settings(global_settings=global_settings)
	s.enable_storage(storage_path)

def disable_storage(storage_path, global_settings=False):
	s = __get_settings(global_settings=global_settings)
	s.disable_storage(storage_path)

def add_storage_folder(storages_folder, global_settings=False):
	s = __get_settings(global_settings=global_settings)
	s.add_folder_storage(storages_folder)

def remove_storage_folder(storages_folder, global_settings=False):
	s = __get_settings(global_settings=global_settings)
	s.remove_storage_folder(storages_folder)

def add_storage_file(storage_path, global_settings=False):
	s = __get_settings(global_settings=global_settings)
	s.add_storage_file(storage_path)

def remove_storage_file(storage_path, global_settings=False):
	s = __get_settings(global_settings=global_settings)
	s.remove_file_storage(storage_path)