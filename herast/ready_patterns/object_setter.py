from collections import defaultdict
import idaapi
import idautils
import herapi
import idc

"""
This example demonstrates how to mass-set objects according to how
they are assigned values in decompiled functions by function calls.
e.g.: 
	dword_123456 = Foo(123, 3, "qwe")
into
	object_7b_3 = Foo(123, 3, "qwe")

FUNC_ADDR variable is needed
In order to better control name/type generation update PATTERN
"""

def get_object_address(item):
	return item.cexpr.x.obj_ea

def get_object_type(item):
	return None

def get_object_name(item):
	addr = item.ea
	item = item.cexpr.y
	if item.op == idaapi.cot_cast:
		item = item.x

	if len(item.a) != 3:
		print("Error: unexpected amount of arguments")
		return None

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
			print(f"Warning: object address {object_address} is already used by object {existing_object_name}")
		if existing_object_type != object_type:
			print(f"Warning: object address {object_address} is already used by object {existing_object_type}")

		self.objects[object_address] = (object_name, object_type)

	def get_objects(self):
		for oaddr, (oname, otype) in self.objects.items():
			yield oaddr, oname, otype


class ObjectSetterScheme(herapi.SPScheme):
	def __init__(self, function_address, objects_collection: ObjectsCollection):
		pattern = herapi.ExInsPat(
			herapi.AsgExprPat(
				herapi.ObjPat(),
				herapi.SkipCasts(herapi.CallExprPat(function_address, ignore_arguments=True)),
			)
		)
		super().__init__("object_setter", pattern)
		self.objects_collection = objects_collection

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		object_address = get_object_address(item)
		object_name    = get_object_name(item)
		object_type    = get_object_type(item)
		self.objects_collection.add_object(object_address, object_name, object_type)
		return False


def collect_objects(function_address, default_type=None):
	if function_address == idaapi.BADADDR:
		print("Error: function address is invalid")
		return

	objects_collection = ObjectsCollection()
	scheme = ObjectSetterScheme(function_address, objects_collection)
	matcher = herapi.Matcher()
	matcher.add_scheme(scheme)
	matcher.match_objects_xrefs(function_address)

	print("Found {} objects".format(len(objects_collection.objects)))
	for oaddr, oname, otype in objects_collection.get_objects():
		print("Setting object: {:x} {} {}".format(oaddr, oname, otype))
		if oname is not None:
			idaapi.set_name(oaddr, oname)

		if otype is not None:
			idc.SetType(oaddr, otype)
		elif default_type is not None:
			idc.SetType(oaddr, default_type)


class AssignmentCounterScheme(herapi.SPScheme):
	def __init__(self, candidates):
		if len(candidates) == 1:
			cand = next(iter(candidates))
			obj_pat = herapi.ObjPat(ea=cand)
		else:
			objects = [herapi.ObjPat(ea=cand) for cand in candidates]
			obj_pat = herapi.OrPat(*objects)

		pattern = herapi.AsgExprPat(herapi.AnyPat(), herapi.SkipCasts(herapi.CallExprPat(obj_pat)))
		super().__init__("assignment_counter", pattern)
		self.count = defaultdict(int)

	def add_assignment(self, func_ea):
		self.count[func_ea] += 1

	def trim_assignments(self, threshold):
		self.count = {k: v for k, v in self.count.items() if v >= threshold}

	def show_stats(self):
		print("got {} assignments".format(len(self.count)))
		for func_ea, count in self.count.items():
			print("{:x} {} {}".format(func_ea, idaapi.get_func_name(func_ea), count))

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		call_expr = item.y
		if call_expr.op == idaapi.cot_cast:
			call_expr = call_expr.x

		func_ea = call_expr.x.obj_ea
		self.add_assignment(func_ea)
		return False

def count_xrefs_to(ea):
	return len([x for x in idautils.XrefsTo(ea)])

def count_assignments(*functions, assignments_amount_threshold=15):
	functions = [f for f in functions if count_xrefs_to(f) > assignments_amount_threshold]

	scheme = AssignmentCounterScheme(functions)
	matcher = herapi.Matcher(scheme)
	matcher.match_objects_xrefs(*functions)

	scheme.trim_assignments(assignments_amount_threshold)
	scheme.show_stats()