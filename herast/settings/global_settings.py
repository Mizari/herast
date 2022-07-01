import os
import idaapi

from herast.settings.base_settings import BaseSettings

def get_settings_path():
	return os.path.join(idaapi.get_user_idadir(), "herast_settings.json")

class HerastSettings(BaseSettings):
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

settings_instance = HerastSettings.create()