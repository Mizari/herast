"""Aggregator module for all underlying herapi API"""

import sys

# forward imports for herast usage
from herast.tree.patterns.abstracts import *
from herast.tree.patterns.expressions import *
from herast.tree.patterns.instructions import *
from herast.tree.patterns.helpers import *

# passive manager imports should go after settings manager imports
# because they might expand behaviour with updating passing manager
from herast.settings.settings_manager import *
from herast.passive_manager import *

from herast.tree.utils import make_call_helper_instr, strip_casts
from herast.tree.matcher import Matcher
from herast.tree.scheme import Scheme

def __print_padded(*args, padlen=0):
	padlen -= 1
	print(' ' * padlen, *args, )

def __help_objects(name, objs):
	if len(objs) == 0:
		return

	print(name)
	for modname in sorted(objs.keys()):
		m = objs[modname]
		__print_padded(modname, padlen=4)
		if m.__doc__:
			__print_padded(m.__doc__, padlen=8)
		print()
	print()

def herapi_help():
	"""Print this help"""
	from inspect import isclass, isfunction, ismodule

	mod = sys.modules[__name__]
	funcs = {}
	modules = {}
	classes = {}
	for k, v in vars(mod).items():
		if k.startswith("__"): continue
		if k.endswith("Pat"):
			continue
		if k in ("sys", "idaapi", "typing", "settings_manager"):
			continue
		if isfunction(v):
			funcs[k] = v
		elif ismodule(v):
			modules[k] = v
		elif isclass(v):
			classes[k] = v
		else:
			pass

	print("DESCRIPTION")
	__print_padded(mod.__doc__, padlen=4)
	print()

	__help_objects("MODULES", modules)
	__help_objects("CLASSES", classes)
	__help_objects("FUNCTIONS", funcs)


def herapi_help_patterns():
	"""Print help on patterns"""

	mod = sys.modules[__name__]
	patterns = {k:v for k, v in vars(mod).items() if k.endswith("Pat")}
	__help_objects("PATTERNS", patterns)