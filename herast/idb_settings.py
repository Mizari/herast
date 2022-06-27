from .tree.utils import save_long_str_to_idb
from .tree.utils import load_long_str_from_idb

import json

ARRAY_NAME = "$herast:PatternStorage"
def get_enabled_idb_storages():
	stored_string = load_long_str_from_idb(ARRAY_NAME) or '[]'
	stored_enabled_array = json.loads(stored_string)
	return stored_enabled_array

def save_enabled_idb_storages(stored_enabled_array):
	save_long_str_to_idb(ARRAY_NAME, json.dumps(stored_enabled_array))

