import idaapi
from herast.tree.patterns.abstracts import PatternContext, SkipCasts, AnyPat
from herast.tree.patterns.expressions import AsgExprPat, CallExprPat, ObjPat
from herast.tree.patterns.instructions import ExInsPat
from herast.tree.matcher import Matcher

from herast.tree.utils import *

from herast.schemes.single_pattern_schemes import SPScheme

FUNC_ADDR = idaapi.BADADDR
PATTERN = ExInsPat(
	AsgExprPat(
		ObjPat(),
		SkipCasts(CallExprPat(FUNC_ADDR, AnyPat(), AnyPat(), AnyPat())),
	)
)

def get_object_address(item):
	return item.cexpr.x.obj_ea

def get_object_type(item):
	return None

def get_object_name(item):
	addr = item.ea
	item = item.cexpr.y
	if item.op == idaapi.cot_cast:
		item = item.x

	arg0 = item.a[0]
	if arg0.op != idaapi.cot_num:
		print("Error: object name is not an integer", hex(addr))
		return None

	arg1 = item.a[1]
	if arg1.op != idaapi.cot_num:
		return None

	arg0 = arg0.n._value
	arg1 = arg1.n._value
	return "object_" + hex(arg0)[2:] + '_' + str(arg1)


class ObjectsCollection:
	def __init__(self):
		self.objects = {}

	def add_object(self, object_address, object_name, object_type):
		if self.objects.get(object_address, None) is None:
			self.objects[object_address] = (object_name, object_type)
			return

		existing_object_name, existing_object_type = self.objects[object_address]
		if object_name is None:
			object_name = existing_object_name
		if object_type is None:
			object_type = existing_object_type

		if existing_object_name != object_name:
			print("Warning: object address {} is already used by object {}".format(object_address, existing_object_name))
		if existing_object_type != object_type:
			print("Warning: object address {} is already used by object {}".format(object_address, existing_object_type))

		self.objects[object_address] = (object_name, object_type)

	def get_objects(self):
		for oaddr, (oname, otype) in self.objects.items():
			yield oaddr, oname, otype


class ObjectSetterScheme(SPScheme):
	def __init__(self, objects_collection: ObjectsCollection):
		super().__init__("object_setter", PATTERN)
		self.objects_collection = objects_collection

	def on_matched_item(self, item, ctx: PatternContext):
		object_address = get_object_address(item)
		object_name    = get_object_name(item)
		object_type    = get_object_type(item)
		self.objects_collection.add_object(object_address, object_name, object_type)
		return False


def get_func_start(addr):
	func = idaapi.get_func(addr)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

def get_func_calls_to(fea):
	rv = filter(None, [get_func_start(x.frm) for x in idautils.XrefsTo(fea)])
	rv = filter(lambda x: x != idaapi.BADADDR, rv)
	return list(rv)


def collect_objects(function_address):
	if function_address == idaapi.BADADDR:
		print("Error: function address is invalid")
		return

	objects_collection = ObjectsCollection()
	scheme = ObjectSetterScheme(objects_collection)
	matcher = Matcher()
	matcher.add_scheme(scheme)

	all_calls = {x for x in get_func_calls_to(function_address)}
	for func_ea in all_calls:
		cfunc = idaapi.decompile(func_ea)
		if cfunc is None:
			print("Failed to decompile function at 0x%x" % func_ea)
			continue
		matcher.match_cfunc(cfunc)

	print("Found {} objects".format(len(objects_collection.objects)))
	for oaddr, oname, otype in objects_collection.get_objects():
		print("Setting object: {:x} {} {}".format(oaddr, oname, otype))
		if oname is not None:
			idaapi.set_name(oaddr, oname)
		if otype is not None:
			idc.SetType(oaddr, otype)


if __name__ == "__main__":
	collect_objects(FUNC_ADDR)