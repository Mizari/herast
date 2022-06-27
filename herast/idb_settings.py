import idc

from herast.storages_settings import StoragesSettings

def load_long_str_from_idb(array_name):
	id = idc.get_array_id(array_name)
	if id == -1:
		return None
	max_idx = idc.get_last_index(idc.AR_STR, id)
	result = [idc.get_array_element(idc.AR_STR, id, idx) for idx in range(max_idx + 1)]
	return b"".join(result).decode("utf-8")


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


ARRAY_NAME = "$herast:PatternStorage"
class IdbSettings(StoragesSettings):
	@classmethod
	def save_json_str(cls, saved_str):
		save_long_str_to_idb(ARRAY_NAME, saved_str)

	@classmethod
	def load_json_str(cls):
		return load_long_str_from_idb(ARRAY_NAME) or '{}'

idb_settings = IdbSettings.create()

def get_enabled_idb_storages():
	return list(idb_settings.enabled)

def save_enabled_idb_storages(stored_enabled_array):
	idb_settings.enabled = stored_enabled_array
	idb_settings.save()