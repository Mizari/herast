import idaapi
import herapi


"""
This script renames functions according to pattern found in them
"""

def make_pattern(debug_flag):
	return herapi.IfInsPat(
		herapi.ObjPat(ea=debug_flag),
		herapi.DeepExpr(herapi.CallExprPat("printf", ignore_arguments=True), bind_name="debug_print"),
		should_wrap_in_block=False, # if to not wrap in block, because we want to search inside block's instructions
	)


class FunctionsRenamings:
	def __init__(self) -> None:
		self.renamings = {}
		self.conflicts = {}

	def add_renaming(self, func_addr, new_name):
		current_name = idaapi.get_func_name(func_addr) 
		if current_name == new_name:
			return

		if func_addr in self.conflicts:
			self.conflicts[func_addr].add(new_name)
			return

		current = self.renamings.get(func_addr)
		if current is not None and current != new_name:
			del self.renamings[func_addr]
			self.conflicts[func_addr] = {current, new_name}
			return

		self.renamings[func_addr] = new_name

	def apply_renamings(self):
		for func_addr, new_name in self.renamings.items():
			print("renaming", hex(func_addr), "to", new_name)
			idaapi.set_name(func_addr, new_name)

	def print_conflicts(self):
		for func_addr, names in self.conflicts.items():
			print("Conflicting renamings:", hex(func_addr), names)

class FunctionRenamer(herapi.SPScheme):
	def __init__(self, renamings_collection, debug_flag):
		self.renamings_collection = renamings_collection
		pattern = make_pattern(debug_flag)
		super().__init__("function_renamer", pattern)

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		func_ea = ctx.get_func_ea()
		debug_print = ctx.get_expr("debug_print")
		s = debug_print.a[1]
		name = s.print1(None)
		name = idaapi.tag_remove(name)
		name = idaapi.str2user(name)
		name = name[2:-2]
		self.renamings_collection.add_renaming(func_ea, name)
		return False


def do_renames(debug_flag: int):
	col = FunctionsRenamings()
	scheme = FunctionRenamer(col, debug_flag)
	matcher = herapi.Matcher(scheme)
	matcher.match_objects_xrefs(debug_flag)

	col.apply_renamings()
	col.print_conflicts()