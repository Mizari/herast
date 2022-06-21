import herapi
import idautils

"""
This example show how to automate objects collecting of this form:
	some_struct_pointer->some_field = some_value;
"""

class VirtualCollector(herapi.SPScheme):
	def __init__(self, struct_type=None, offset=None):
		pattern = herapi.AsgExprPat(herapi.StructMemptr(struct_type, offset), herapi.AnyPat())
		super().__init__("virtual_collector", pattern)
		self.collection = []

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		func_ea = herapi.get_func_start(item.ea)
		struct_type = item.x.x.type.get_pointed_object()
		offset = item.x.m
		value = item.y
		self.collection.append((func_ea, struct_type, offset, value))
		return False

def collect_virtual_properties(functions=idautils.Functions(), struct_type=None, offset=None):
	scheme = VirtualCollector(struct_type, offset)
	matcher = herapi.Matcher(scheme)

	cfuncs = {ea: herapi.get_cfunc(ea) for ea in functions}
	for ea, cfunc in cfuncs.items():
		if cfunc is None:
			continue
		matcher.match_cfunc(cfunc)

	for func_ea, struct_type, offset, value in scheme.collection:
		yield func_ea, struct_type, offset, value