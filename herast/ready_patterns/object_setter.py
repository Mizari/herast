from collections import defaultdict
import idaapi
import idautils
import herapi
import idc

"""
This example demonstrates how to mass-set objects according to how
they are assigned values in decompiled functions by function calls.
e.g.: 
	dword_1337 = Foo(arg1, arg2)

FUNC_ADDR variable is needed
In order to better control name/type generation update PATTERN
"""

# this pattern in scheme turns
# dword_123456 = Foo(123, 3, "qwe")
# into
# object_7b_3 = Foo(123, 3, "qwe")
def make_pattern(function_address):
	return herapi.ExInsPat(
		herapi.AsgExprPat(
			herapi.ObjPat(),
			herapi.SkipCasts(herapi.CallExprPat(function_address, ignore_arguments=True)),
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
			print("Warning: object address {} is already used by object {}".format(object_address, existing_object_name))
		if existing_object_type != object_type:
			print("Warning: object address {} is already used by object {}".format(object_address, existing_object_type))

		self.objects[object_address] = (object_name, object_type)

	def get_objects(self):
		for oaddr, (oname, otype) in self.objects.items():
			yield oaddr, oname, otype


class ObjectSetterScheme(herapi.SPScheme):
	def __init__(self, function_address, objects_collection: ObjectsCollection):
		pattern = make_pattern(function_address)
		super().__init__("object_setter", pattern)
		self.objects_collection = objects_collection

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		object_address = get_object_address(item)
		object_name    = get_object_name(item)
		object_type    = get_object_type(item)
		self.objects_collection.add_object(object_address, object_name, object_type)
		return False


def get_func_calls_to(fea):
	rv = filter(None, [herapi.get_func_start(x.frm) for x in idautils.XrefsTo(fea)])
	rv = filter(lambda x: x != idaapi.BADADDR, rv)
	return list(rv)


def collect_objects(function_address, default_type=None):
	if function_address == idaapi.BADADDR:
		print("Error: function address is invalid")
		return

	objects_collection = ObjectsCollection()
	scheme = ObjectSetterScheme(function_address, objects_collection)
	matcher = herapi.Matcher()
	matcher.add_scheme(scheme)

	for func_ea in get_func_calls_to(function_address):
		cfunc = herapi.get_cfunc(func_ea)
		if cfunc is None:
			continue
		matcher.match_cfunc(cfunc)

	print("Found {} objects".format(len(objects_collection.objects)))
	for oaddr, oname, otype in objects_collection.get_objects():
		print("Setting object: {:x} {} {}".format(oaddr, oname, otype))
		if oname is not None:
			idaapi.set_name(oaddr, oname)

		if otype is not None:
			idc.SetType(oaddr, otype)
		elif default_type is not None:
			idc.SetType(oaddr, default_type)

class AssignmentCounter:
	def __init__(self):
		self.count = defaultdict(int)

	def clear(self):
		self.count.clear()

	def add_assignment(self, func_ea):
		self.count[func_ea] += 1

	def trim_assignments(self, threshold):
		self.count = {k: v for k, v in self.count.items() if v >= threshold}

	def show_stats(self):
		print("got {} assignments".format(len(self.count)))
		for func_ea, count in self.count.items():
			print("{:x} {} {}".format(func_ea, idaapi.get_func_name(func_ea), count))

class AssignmentCounterScheme(herapi.SPScheme):
	def __init__(self, counter: AssignmentCounter, candidates):
		if len(candidates) == 1:
			cand = next(iter(candidates))
			obj_pat = herapi.ObjPat(ea=cand)
		else:
			objects = [herapi.ObjPat(ea=cand) for cand in candidates]
			obj_pat = herapi.OrPat(*objects)

		pattern = herapi.AsgExprPat(herapi.AnyPat(), herapi.SkipCasts(herapi.CallExprPat(obj_pat)))
		super().__init__("assignment_counter", pattern)
		self.counter = counter

	def on_tree_iteration_start(self, ctx: herapi.PatternContext):
		print("starting")
		self.counter.clear()

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		call_expr = item.y
		if call_expr.op == idaapi.cot_cast:
			call_expr = call_expr.x

		func_ea = call_expr.x.obj_ea
		print("adding", hex(func_ea), "in", hex(ctx.tree_proc.cfunc.entry_ea), item.opname, hex(item.ea))
		self.counter.add_assignment(func_ea)
		return False


def count_assignments(functions=idautils.Functions, assignments_amount_threshold=15):
	cfuncs_eas = set()
	candidates = set()
	for func_ea in functions:
		calls = get_func_calls_to(func_ea)
		if len(calls) < assignments_amount_threshold:
			continue

		candidates.add(func_ea)
		cfuncs_eas.update(calls)

	print("found {} candidates".format(len(candidates)))
	print("need to decompile {} cfuncs".format(len(cfuncs_eas)))

	cfuncs = {ea: herapi.get_cfunc(ea) for ea in cfuncs_eas}
	counter = AssignmentCounter()
	scheme = AssignmentCounterScheme(counter, candidates)
	matcher = herapi.Matcher(scheme)

	for cfunc in cfuncs.values():
		if cfunc is None:
			continue

		matcher.match_cfunc(cfunc)

	counter.trim_assignments(assignments_amount_threshold)
	counter.show_stats()