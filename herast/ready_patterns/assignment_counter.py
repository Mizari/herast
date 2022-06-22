import herapi
import idautils
import idaapi
from collections import defaultdict


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