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


def herapi_help():
	"""Print this help"""
	from inspect import isclass, isfunction, ismodule

	def print_padded(*args, padlen=0):
		padlen -= 1
		print(' ' * padlen, *args, )

	mod = sys.modules[__name__]
	funcs = {}
	modules = {}
	classes = {}
	for k, v in vars(mod).items():
		if k.startswith("__"): continue
		if k.endswith("Pat"):
			classes[k] = v
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
	print_padded(mod.__doc__, padlen=4)
	print()

	if len(modules) != 0:
		print("MODULES")
		for modname in sorted(modules.keys()):
			m = modules[modname]
			print_padded(modname, padlen=4)
			if m.__doc__:
				print_padded(m.__doc__, padlen=8)
			print()
		print()

	print("CLASSES")
	# first print non-patterns
	for classname in sorted(classes.keys()):
		c = classes[classname]
		if classname.endswith("Pat"): continue
		print_padded(classname, padlen=4)
		if c.__doc__:
			print_padded(c.__doc__, padlen=8)
		print()

	for classname in sorted(classes.keys()):
		c = classes[classname]
		if not classname.endswith("Pat"): continue
		print_padded(classname, isinstance(c, BasePat), padlen=4)
		if c.__doc__:
			print_padded(c.__doc__, padlen=8)
		print()
	print()

	print("FUNCTIONS")
	for fname in sorted(funcs.keys()):
		f = funcs[fname]
		print_padded(fname, padlen=4)
		if f.__doc__:
			print_padded(f.__doc__, padlen=8)
		print()
	print()