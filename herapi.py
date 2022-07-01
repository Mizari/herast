# forward imports for herast usage
from herast.tree.patterns.abstracts import *
from herast.tree.patterns.expressions import *
from herast.tree.patterns.instructions import *
from herast.tree.patterns.helpers import *
from herast.tree.utils import make_call_helper_instr, strip_casts
from herast.tree.matcher import Matcher
from herast.passive_manager import *
from herast.schemes.single_pattern_schemes import SPScheme, ItemRemovalScheme
from herast.settings.herast_settings import get_herast_enabled_storages_paths, get_herast_storages_filenames, get_herast_storages_folders, enable_herast_storage, add_herast_storage_file, add_herast_storage_folder
from herast.settings.idb_settings import get_idb_enabled_storages_paths, get_idb_storages_filenames, get_idb_storages_folders, enable_idb_storage, add_idb_storage_file, add_idb_storage_folder