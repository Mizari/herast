import json

class BaseSettings:
	"""Base class for all possible settings."""
	def __init__(self, folders=[], files=[], storages_statuses={}, schemes_statuses={}, time_matching=None):
		self.storages_folders = folders
		self.storages_files = files
		self.storages_statuses = storages_statuses
		self.schemes_statuses = schemes_statuses
		self.time_matching = time_matching

	def add_storage_file(self, file_path: str):
		if file_path in self.storages_files:
			return
		self.storages_files.append(file_path)
		self.save()

	def add_folder_storage(self, storages_folder: str):
		if storages_folder in self.storages_folders:
			return
		self.storages_folders.append(storages_folder)
		self.save()

	def enable_storage(self, storage_path: str):
		self.storages_statuses[storage_path] = "enabled"
		self.save()

	def disable_storage(self, storage_path: str):
		self.storages_statuses[storage_path] = "disabled"
		self.save()
	
	def enable_scheme(self, scheme_name: str):
		self.schemes_statuses[scheme_name] = "enabled"
		self.save()

	def disable_scheme(self, scheme_name: str):
		self.schemes_statuses[scheme_name] = "disabled"
		self.save()

	def remove_file_storage(self, file_path: str):
		if file_path not in self.storages_files:
			return
		self.storages_files.remove(file_path)
		self.save()

	def remove_storage_folder(self, folder_path: str):
		if folder_path not in self.storages_folders:
			return
		self.storages_folders.remove(folder_path)
		self.save()

	@classmethod
	def load_json_str(cls):
		raise NotImplementedError()

	@classmethod
	def save_json_str(cls, saved_str: str):
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
		storages_statuses = json_dict.get("storages_statuses", {})
		schemes_statuses = json_dict.get("schemes_statuses", {})
		time_matching = json_dict.get("time_matching", None)
		if check(files) and check(folders) and isinstance(storages_statuses, dict):
			return cls(
				files=files,
				folders=folders,
				storages_statuses=storages_statuses,
				schemes_statuses=schemes_statuses,
				time_matching=time_matching
			)
		else:
			return None

	def save(self):
		json_dict = {
			"folders": self.storages_folders,
			"files":   self.storages_files,
			"storages_statuses": self.storages_statuses,
			"schemes_statuses": self.schemes_statuses,
		}
		if self.time_matching is not None:
			json_dict["time_matching"] = self.time_matching
		json_str = json.dumps(json_dict)
		self.save_json_str(json_str)