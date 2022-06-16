import herast.storage_manager as storage_manager

def get_storages():
	return [s for s in storage_manager.schemes_storages.values()]

def get_storage(storage_path):
	return storage_manager.get_storage(storage_path)