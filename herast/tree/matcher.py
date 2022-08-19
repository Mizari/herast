import idaapi
import idautils

from herast.tree.patterns.abstracts import BindItemPat, VarBindPat
from herast.tree.pattern_context import PatternContext
from herast.tree.processing import TreeProcessor
from herast.tree.scheme import Scheme


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
		self.schemes : dict[str, Scheme] = {s.name: s for s in schemes}

	def match(self, func):
		"""Match schemes for function body.

		:param func: matched function. Can be decompiled or just function address"""
		if func is None:
			return

		if isinstance(func, idaapi.cfunc_t):
			return self.match_cfunc(func)

		if isinstance(func, int):
			cfunc = get_cfunc(func)
			if cfunc is None:
				return
			return self.match_cfunc(cfunc)

		raise Exception("Invalid function type")

	def match_objects_xrefs(self, *objects):
		"""Match objects' xrefs in functions. Might decompile a lot of functions"""
		cfuncs_eas = set()
		for func_ea in objects:
			calls = get_func_calls_to(func_ea)
			cfuncs_eas.update(calls)

		print("need to decompile {} cfuncs".format(len(cfuncs_eas)))
		for func_ea in cfuncs_eas:
			cfunc = get_cfunc(func_ea)
			if cfunc is None:
				continue
			self.match_cfunc(cfunc)

	def match_everywhere(self):
		for func_ea in idautils.Functions(0, idaapi.BADADDR):
			self.match(func_ea)

	def match_instruction(self, instr_addr):
		func_addr = get_func_start(instr_addr)
		cfunc = get_cfunc(func_addr)
		if cfunc is None: return

		tree_processor = TreeProcessor(cfunc)
		for subitem in tree_processor.iterate_subinstrs(cfunc.body):
			if subitem.ea == instr_addr:
				self.match_ast_tree(tree_processor, subitem)
				break

	def match_cfunc(self, cfunc):
		"""Match schemes in decompiled function."""
		tree_processor = TreeProcessor(cfunc)
		ast_tree = cfunc.body
		self.match_ast_tree(tree_processor, ast_tree)

	def match_ast_tree(self, tree_processor: TreeProcessor, ast_tree):
		while True:
			contexts = {s.name: PatternContext(tree_processor) for s in self.schemes.values()}
			for scheme_name, scheme in self.schemes.items():
				scheme.on_tree_iteration_start(contexts[scheme_name])

			is_tree_modified = False
			for subitem in tree_processor.iterate_subitems(ast_tree):
				is_tree_modified = self.check_schemes(tree_processor, subitem)
				if is_tree_modified:
					break

			if not is_tree_modified:
				break

			for scheme_name, scheme in self.schemes.items():
				scheme.on_tree_iteration_end(contexts[scheme_name])

	def check_schemes(self, tree_processor: TreeProcessor, item: idaapi.citem_t) -> bool:
		"""Match item in schemes.

		:param tree_processor:
		:param item: AST item
		:return: is item modified/removed?
		"""
		item_ctx = PatternContext(tree_processor)

		for scheme in self.schemes.values():
			if self.check_scheme(scheme, item, item_ctx):
				return True

			if self.finalize_item_context(item_ctx):
				return True

		return False

	def check_scheme(self, scheme: Scheme, item: idaapi.citem_t, item_ctx: PatternContext):
		try:
			item_ctx.cleanup()
		except Exception as e:
			print('[!] Got an exception during context cleanup: %s' % e)
			return False

		try:
			if not scheme.on_new_item(item, item_ctx):
				return False
		except Exception as e:
			print('[!] Got an exception during pattern matching: %s' % e)
			return False

		try:
			is_tree_modified = scheme.on_matched_item(item, item_ctx)
			if not isinstance(is_tree_modified, bool):
				raise Exception("Handler return invalid return type, should be bool")

			if is_tree_modified:
				return True
		except Exception as e:
			print('[!] Got an exception during pattern handling: %s' % e)
			return False

	def finalize_item_context(self, ctx: PatternContext):
		tree_proc = ctx.tree_proc
		is_tree_modified = False
		for modified_instr in ctx.modified_instrs():
			item = modified_instr.item
			new_item = modified_instr.new_item

			if new_item is None:
				if tree_proc.remove_item(item):
					is_tree_modified = True
			elif tree_proc.replace_item(item, new_item):
				is_tree_modified = True

		return is_tree_modified

	def get_scheme(self, scheme_name: str):
		return self.schemes.get(scheme_name)

	def add_scheme(self, scheme: Scheme):
		self.schemes[scheme.name] = scheme

	def remove_scheme(self, scheme_name: str):
		self.schemes.pop(scheme_name, None)

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = (VarBindPat, BindItemPat)
		for s in self.schemes.values():
			for p in s.get_patterns():
				if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, abstract_expression_patterns):
					return True

		return False