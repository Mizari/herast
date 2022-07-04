import json

class BaseSettings:
	def __init__(self, folders=[], files=[], enabled=[], time_matching=None):
		self.storages_folders = folders
		self.storages_files = files
		self.enabled_storages = enabled
		self.time_matching = time_matching

	def add_storage_file(self, file_path):
		if file_path in self.storages_files:
			return
		self.storages_files.append(file_path)
		self.save()

	def add_folder_storage(self, storages_folder):
		if storages_folder in self.storages_folders:
			return
		self.storages_folders.append(storages_folder)
		self.save()

	def enable_storage(self, storage_path):
		if storage_path in self.enabled_storages:
			return
		self.enabled_storages.append(storage_path)
		self.save()

	def disable_storage(self, storage_path):
		if storage_path not in self.enabled_storages:
			return
		self.enabled_storages.remove(storage_path)
		self.save()

	def remove_file_storage(self, file_path):
		if file_path not in self.storages_files:
			return
		self.storages_files.remove(file_path)
		self.save()

	def remove_storage_folder(self, folder_path):
		if folder_path not in self.storages_folders:
			return
		self.storages_folders.remove(folder_path)
		self.save()

	@classmethod
	def load_json_str(cls):
		raise NotImplementedError()

	@classmethod
	def save_json_str(cls, saved_str):
		raise NotImplementedError()

	@classmethod
	def create(cls):
		json_str = cls.load_json_str()
		if json_str is None:
			return None

		try:
			json_dict = json.loads(json_str)
		except:
			return None

		if not isinstance(json_dict, dict):
			print("[!] WARNING: invalid serialized storages settings, using empty")
			json_dict = {}

		def check(x):
			if x is None: return True
			if not isinstance(x, list): return False
			if any(not isinstance(i, str) for i in x): return False
			return True

		files = json_dict.get("files", [])
		folders = json_dict.get("folders", [])
		enabled = json_dict.get("enabled", [])
		time_matching = json_dict.get("time_matching", None)
		if check(files) and check(folders) and check(enabled):
			return cls(files=files, folders=folders, enabled=enabled, time_matching=time_matching)
		else:
			return None

	def save(self):
		json_dict = {
			"folders": self.storages_folders,
			"files":   self.storages_files,
			"enabled": self.enabled_storages,
		}
		if self.time_matching is not None:
			json_dict["time_matching"] = self.time_matching
		json_str = json.dumps(json_dict)
		self.save_json_str(json_str)