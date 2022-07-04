from herast.settings.idb_settings import settings_instance as __idb_settings
from herast.settings.global_settings import settings_instance as __global_settings


# By default settings getters return global settings overwritten by idb settings

def get_storages_statuses(in_idb=False, globally=False):
	if in_idb:
		return dict(__idb_settings.storages_statuses)
	if globally:
		return dict(__global_settings.storages_statuses)

	d = dict(__global_settings.storages_statuses)
	d.update(__idb_settings.storages_statuses)
	return d

def get_storage_status(storage_path, in_idb=False, globally=False):
	d = get_storages_statuses(in_idb=in_idb, globally=globally)
	return d.get(storage_path, "disabled")

def get_storages_folders(in_idb=False, globally=False):
	if in_idb:
		return list(__idb_settings.storages_folders)
	if globally:
		return list(__global_settings.storages_folders)

	return __idb_settings.storages_folders + __global_settings.storages_folders

def get_storages_files(in_idb=False, globally=False):
	if in_idb:
		return list(__idb_settings.storages_files)
	if globally:
		return list(__global_settings.storages_files)

	return __idb_settings.storages_files + __idb_settings.storages_files

def get_time_matching(in_idb=False, globally=False):
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

def __get_settings(globally=False):
	if globally:
		return __global_settings
	else:
		return __idb_settings

def enable_storage(storage_path, global_settings=False):
	s = __get_settings(globally=global_settings)
	s.enable_storage(storage_path)

def disable_storage(storage_path, global_settings=False):
	s = __get_settings(globally=global_settings)
	s.disable_storage(storage_path)

def add_storage_folder(storages_folder, global_settings=False):
	s = __get_settings(globally=global_settings)
	s.add_folder_storage(storages_folder)

def remove_storage_folder(storages_folder, global_settings=False):
	s = __get_settings(globally=global_settings)
	s.remove_storage_folder(storages_folder)

def add_storage_file(storage_path, global_settings=False):
	s = __get_settings(globally=global_settings)
	s.add_storage_file(storage_path)

def remove_storage_file(storage_path, global_settings=False):
	s = __get_settings(globally=global_settings)
	s.remove_file_storage(storage_path)