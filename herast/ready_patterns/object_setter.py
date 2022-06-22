from collections import defaultdict
import idaapi
import idautils
import herapi
import idc


"""
This example demonstrates how to mass-set objects according to how
they are assigned values by function calls.
e.g.: 
	dword_123456 = Foo(123, 3, "qwe")
into
	object_7b_3 = Foo(123, 3, "qwe")
"""
class ObjectSetterScheme(herapi.SPScheme):
	def __init__(self, function_address):
		self.objects = {}
		call_pattern = herapi.SkipCasts(herapi.CallExprPat(function_address, herapi.NumPat(), herapi.NumPat(), herapi.AnyPat()))
		pattern = herapi.AsgExprPat(herapi.ObjPat(), call_pattern)
		super().__init__("object_setter", pattern)

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		asg_y = herapi.skip_casts(item.y)
		arg0 = asg_y.a[0].n._value
		arg1 = asg_y.a[1].n._value
		object_name = "object_" + hex(arg0)[2:] + '_' + str(arg1)
		object_address = item.x.obj_ea
		object_type    = None
		self.add_object(object_address, object_name, object_type)
		return False

	def add_object(self, object_ea, object_name, object_type):
		if self.objects.get(object_ea) is None:
			self.objects[object_ea] = (object_name, object_type)
			return

		existing_object_name, existing_object_type = self.objects[object_ea]
		if object_name is None:
			object_name = existing_object_name
		if object_type is None:
			object_type = existing_object_type

		if existing_object_name != object_name:
			print(f"Warning: object address {object_ea} is already used by object {existing_object_name}")
		if existing_object_type != object_type:
			print(f"Warning: object address {object_ea} is already used by object {existing_object_type}")

		self.objects[object_ea] = (object_name, object_type)

	def apply_new_info(self, default_type=None):
		print("Found {} objects".format(len(self.objects)))
		for oaddr, (oname, otype) in self.objects:
			print("Setting object: {:x} {} {}".format(oaddr, oname, otype))
			if oname is not None:
				idaapi.set_name(oaddr, oname)

			if otype is not None:
				idc.SetType(oaddr, otype)
			elif default_type is not None:
				idc.SetType(oaddr, default_type)


def collect_objects(function_address, default_type=None):
	if function_address == idaapi.BADADDR:
		print("Error: function address is invalid")
		return

	scheme = ObjectSetterScheme(function_address)
	matcher = herapi.Matcher()
	matcher.add_scheme(scheme)
	matcher.match_objects_xrefs(function_address)
	scheme.apply_new_info(default_type)


class AssignmentCounterScheme(herapi.SPScheme):
	def __init__(self, *candidates):
		if len(candidates) == 1:
			cand = candidates[0]
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

	scheme = AssignmentCounterScheme(*functions)
	matcher = herapi.Matcher(scheme)
	matcher.match_objects_xrefs(*functions)

	scheme.trim_assignments(assignments_amount_threshold)
	scheme.show_stats()