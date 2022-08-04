import idc

from herast.settings.base_settings import BaseSettings

def load_long_str_from_idb(array_name):
	id = idc.get_array_id(array_name)
	if id == -1:
		print("Failed to get array id with name", array_name)
		return None

	max_idx = idc.get_last_index(idc.AR_STR, id)
	result = [idc.get_array_element(idc.AR_STR, id, idx) for idx in range(max_idx + 1)]
	result = b"".join(result)
	return result.decode("utf-8")


def save_long_str_to_idb(array_name, value):
	""" Overwrites old array completely in process """
	id = idc.get_array_id(array_name)
	if id != -1:
		idc.delete_array(id)
	id = idc.create_array(array_name)
	r = []
	for idx in range(len(value) // 1024 + 1):
		s = value[idx * 1024: (idx + 1) * 1024]
		r.append(s)
		idc.set_array_string(id, idx, s)


class IdbSettings(BaseSettings):
	"""Class for settings, stored for per project in IDB."""

	array_name = "$herast:PatternStorage"

	@classmethod
	def save_json_str(cls, saved_str):
		save_long_str_to_idb(cls.array_name, saved_str)

	@classmethod
	def load_json_str(cls):
		x = load_long_str_from_idb(cls.array_name)
		if x is None:
			x = '{' + '}'
			cls.save_json_str(x)
		return x

settings_instance = IdbSettings.create()

def reload_settings():
	global settings_instance
	settings_instance = IdbSettings.create()