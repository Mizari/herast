import herast.storage_manager as storage_manager

# forward imports for herast usage
from herast.tree.patterns.abstracts import *
from herast.tree.patterns.expressions import *
from herast.tree.patterns.instructions import *
from herast.tree.matcher import Matcher
from herast.schemes.single_pattern_schemes import SPScheme

def get_storages():
	return [s for s in storage_manager.schemes_storages.values()]

def get_storage(storage_path):
	return storage_manager.get_storage(storage_path)