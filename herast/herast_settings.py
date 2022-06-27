import os

storages_folders = set()
default_storage_dir = os.path.dirname(__file__) + "\\ready_patterns\\"
if os.path.exists(default_storage_dir):
	storages_folders.add(default_storage_dir)
storages_files = set()

def get_storages_folders():
	return list(storages_folders)

def get_storages_files():
	return list(storages_files)