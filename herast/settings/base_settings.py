import json

class BaseSettings:
	def __init__(self, folders=[], files=[], enabled=[]):
		self.folders = folders
		self.files = files
		self.enabled = enabled

	def add_file_storage(self, file_path):
		if file_path in self.files:
			return
		self.files.append(file_path)
		self.save()

	def add_folder_storage(self, folder_path):
		if folder_path in self.folders:
			return
		self.folders.append(folder_path)
		self.save()

	def add_enabled_storage(self, enabled_path):
		if enabled_path in self.enabled:
			return
		self.enabled.append(enabled_path)
		self.save()

	def remove_enabled_storage(self, enabled_path):
		if enabled_path not in self.enabled:
			return
		self.enabled.remove(enabled_path)
		self.save()

	def remove_file_storage(self, file_path):
		if file_path not in self.files:
			return
		self.files.remove(file_path)
		self.save()

	def remove_folder_storage(self, folder_path):
		if folder_path not in self.folders:
			return
		self.folders.remove(folder_path)
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
		if check(files) and check(folders) and check(enabled):
			return cls(files=files, folders=folders, enabled=enabled)
		else:
			return None

	def save(self):
		json_dict = {
			"folders": self.folders,
			"files":   self.files,
			"enabled": self.enabled,
		}
		json_str = json.dumps(json_dict)
		self.save_json_str(json_str)