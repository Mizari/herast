import idaapi
import idautils

from herast.tree.patterns.abstracts import BindItem, VarBind
from herast.tree.pattern_context import PatternContext
from herast.tree.processing import TreeProcessor
from herast.schemes.base_scheme import Scheme


def get_func_calls_to(fea):
	rv = filter(None, [get_func_start(x.frm) for x in idautils.XrefsTo(fea)])
	rv = filter(lambda x: x != idaapi.BADADDR, rv)
	return list(rv)

def get_func_start(addr):
	func = idaapi.get_func(addr)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

def get_cfunc(func_ea):
	try:
		cfunc = idaapi.decompile(func_ea)
	except idaapi.DecompilationFailure:
		print("Error: failed to decompile function {}".format(hex(func_ea)))
		return None

	if cfunc is None:
		print("Error: failed to decompile function {}".format(hex(func_ea)))
	return cfunc


class Matcher:
	def __init__(self, *schemes):
		self.schemes : list[Scheme] = list(schemes)

	def match(self, func):
		if func is None:
			return

		if isinstance(func, idaapi.cfunc_t):
			return self.match_cfunc(func)

		if isinstance(func, int):
			cfunc = get_cfunc(func)
			if cfunc is None:
				return False
			return self.match_cfunc(cfunc)

		raise Exception("Invalid function type")

	def match_objects_xrefs(self, *objects):
		cfuncs_eas = set()
		for func_ea in objects:
			calls = get_func_calls_to(func_ea)
			cfuncs_eas.update(calls)

		print("need to decompile {} cfuncs".format(len(cfuncs_eas)))
		for cfunc in cfuncs_eas:
			if cfunc is None:
				continue
			self.match_cfunc(cfunc)

	def match_cfunc(self, cfunc):
		def processing_callback(tree_proc, item):
			return self.check_schemes(tree_proc, item)

		tp = TreeProcessor(cfunc)
		if self.expressions_traversal_is_needed():
			tp.process_all_items(cfunc.body, processing_callback)
		else:
			tp.process_all_instrs(cfunc.body, processing_callback)

	def check_schemes(self, tree_processor: TreeProcessor, item: idaapi.citem_t) -> bool:
		item_ctx = PatternContext(tree_processor)

		for scheme in self.schemes:
			self.check_scheme(scheme, item, item_ctx)
			if tree_processor.is_tree_modified:
				return True

			self.finalize_item_context(item_ctx)
			if tree_processor.is_tree_modified:
				return True

		return False

	def check_scheme(self, scheme: Scheme, item: idaapi.citem_t, item_ctx: PatternContext):
		try:
			item_ctx.cleanup()
		except Exception as e:
			print('[!] Got an exception during context cleanup: %s' % e)
			return

		try:
			if not scheme.on_new_item(item, item_ctx):
				return
		except Exception as e:
			print('[!] Got an exception during pattern matching: %s' % e)
			return

		try:
			is_tree_modified = scheme.on_matched_item(item, item_ctx)
			if not isinstance(is_tree_modified, bool):
				raise Exception("Handler return invalid return type, should be bool")

			if is_tree_modified:
				return
		except Exception as e:
			print('[!] Got an exception during pattern handling: %s' % e)
			return

	def finalize_item_context(self, ctx: PatternContext):
		tree_proc = ctx.tree_proc
		for modified_instr in ctx.modified_instrs():
			item = modified_instr.item
			new_item = modified_instr.new_item

			if new_item is None:
				tree_proc.remove_item(item)
			else:
				tree_proc.replace_item(item, new_item)

	def add_scheme(self, scheme):
		self.schemes.append(scheme)

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = (VarBind, BindItem)
		for s in self.schemes:
			for p in s.get_patterns():
				if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, abstract_expression_patterns):
					return True

		return False