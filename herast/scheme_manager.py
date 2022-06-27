import herast.storage_manager as storage_manager
from herast.schemes.base_scheme import Scheme


passive_schemes = {}

def add_passive_scheme(scheme):
	if not isinstance(scheme, Scheme):
		return

	passive_schemes[scheme.name] = scheme

def get_passive_schemes():
	return [s for s in passive_schemes.values()]