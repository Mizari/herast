import os
import idaapi

from herast.storages_settings import StoragesSettings

def get_settings_path():
	return os.path.join(idaapi.get_user_idadir(), "herast_settings.json")

class HerastSettings(StoragesSettings):
	@classmethod
	def save_json_str(cls, saved_str):
		with open(get_settings_path(), 'w') as f:
			f.write(saved_str)

	@classmethod
	def load_json_str(cls):
		if not os.path.exists(get_settings_path()):
			print("[!] WARNING: settings file does not exist, creating empty one")
			json_str = "{}"
			cls.save_json_str(json_str)
			return json_str

		with open(get_settings_path(), 'r') as f:
			return f.read()

herast_settings = HerastSettings.create()


def get_herast_folders():
	return list(herast_settings.folders)

def get_herast_files():
	return list(herast_settings.files)

def add_herast_file(file_path):
	if file_path in herast_settings.files:
		return
	herast_settings.files.append(file_path)
	herast_settings.save()

def add_herast_folder(folder_path):
	if folder_path in herast_settings.folders:
		return
	herast_settings.folders.append(folder_path)
	herast_settings.save()