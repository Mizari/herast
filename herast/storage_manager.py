import glob

from herast.schemes_storage import SchemesStorage

from typing import Dict, Optional

import herast.idb_settings as idb_settings
import herast.herast_settings as herast_settings


schemes_storages : Dict[str, SchemesStorage] = {}


def load_all_storages():
	for folder in herast_settings.get_storages_folders():
		load_storage_folder(folder)
	for file in herast_settings.get_storages_files():
		load_storage_file(file)

def load_storage_folder(folder_name: str) -> None:
	for full_path in glob.iglob(folder_name + '/**/**.py', recursive=True):
		load_storage_file(full_path)

def load_storage_file(filename: str) -> bool:
	storage = SchemesStorage.from_file(filename)
	if storage is None:
		print("[!] WARNING: failed to load", filename, "storage")
		return False

	storage.enabled = filename in idb_settings.get_enabled_idb_storages()
	schemes_storages[filename] = storage
	return True

def get_storage(filename: str) -> Optional[SchemesStorage]:
	return schemes_storages.get(filename, None)

def get_enabled_storages():
	return [s for s in schemes_storages.values() if s.enabled]