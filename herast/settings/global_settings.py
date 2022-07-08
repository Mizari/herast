import os
import idaapi

from herast.settings.base_settings import BaseSettings

class HerastSettings(BaseSettings):
	"""Class for global settings, usually saved in
	C:\\Users\\USERNAME\\AppData\\Roaming\\Hex-Rays\\IDA Pro\\herast_settings.json
	"""

	path = os.path.join(idaapi.get_user_idadir(), "herast_settings.json")

	def __init__(self, folders=..., files=..., statuses=..., time_matching=None):
		super().__init__(folders, files, statuses, time_matching)

	@classmethod
	def save_json_str(cls, saved_str):
		with open(cls.path, 'w') as f:
			f.write(saved_str)

	@classmethod
	def load_json_str(cls):
		if not os.path.exists(cls.path):
			print("[!] WARNING: settings file does not exist, creating empty one")
			json_str = "{}"
			cls.save_json_str(json_str)
			return json_str

		with open(cls.path, 'r') as f:
			return f.read()

settings_instance = HerastSettings.create()