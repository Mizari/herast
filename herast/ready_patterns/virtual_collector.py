import idaapi
from herast.tree.patterns.abstracts import OrPat, PatternContext, SkipCasts, AnyPat, StructMemptr
from herast.tree.patterns.expressions import AsgExprPat, CallExprPat, ObjPat
from herast.tree.patterns.instructions import ExInsPat
from herast.tree.matcher import Matcher

from herast.tree.utils import *

from herast.schemes.single_pattern_schemes import SPScheme


def get_func_start(addr):
	func = idaapi.get_func(addr)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

class VirtualCollector(SPScheme):
	def __init__(self, struct_type=None, offset=None):
		pattern = AsgExprPat(StructMemptr(struct_type, offset), AnyPat())
		super().__init__("virtual_collector", pattern)
		self.collection = []

	def on_matched_item(self, item, ctx: PatternContext):
		func_ea = get_func_start(item.ea)
		struct_type = item.x.x.type.get_pointed_object()
		offset = item.x.x.m
		value = item.y
		self.collection.append((func_ea, struct_type, offset, value))
		return False

def get_cfunc(func_ea):
	try:
		cfunc = idaapi.decompile(func_ea)
	except:
		print("Error: failed to decompile function {x}".format(hex(func_ea)))
		return None

	if cfunc is None:
		print("Error: failed to decompile function {x}".format(hex(func_ea)))
	return cfunc

def collect_virtual_properties(functions=idautils.Functions(), struct_type=None, offset=None):
	scheme = VirtualCollector(struct_type, offset)
	matcher = Matcher(scheme)

	cfuncs = {ea: get_cfunc(ea) for ea in functions}
	for ea, cfunc in cfuncs.items():
		matcher.match_cfunc(cfunc)

	print("Collected:")
	for func_ea, struct_type, offset, value in scheme.collection:
		print("{} {} {} {}".format(hex(func_ea), struct_type, offset, value.opname))