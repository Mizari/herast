import herast.storage_manager as storage_manager
from herast.schemes.base_scheme import Scheme


def get_enabled_schemes():
	enabled_schemes = []
	for storage in storage_manager.get_enabled_storages():
		for scheme in storage.module.__exported:
			assert isinstance(scheme, Scheme)
			enabled_schemes.append(scheme)
	return enabled_schemes