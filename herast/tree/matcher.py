from __future__ import annotations

import idaapi
import idc

import herast.tree.utils as utils
from herast.tree.pattern_context import PatternContext
from herast.tree.processing import TreeProcessor
from herast.tree.scheme import Scheme
from herast.settings import runtime_settings


class Matcher:
	def __init__(self, *schemes):
		self.schemes : dict[str, Scheme] = {"scheme" + str(i): s for i, s in enumerate(schemes)}

	def match(self, *functions):
		"""Match schemes for function body.

		:param functions: matched functions. Can be decompiled cfuncs, function addresses or function names"""
		for func in functions:
			if isinstance(func, idaapi.cfunc_t):
				self.match_cfunc(func)

			elif isinstance(func, str):
				addr = idc.get_name_ea_simple(func)
				cfunc = utils.get_cfunc(addr)
				if cfunc is None:
					continue
				self.match_cfunc(cfunc)

			elif isinstance(func, int):
				cfunc = utils.get_cfunc(func)
				if cfunc is None:
					continue
				self.match_cfunc(cfunc)

			else:
				raise TypeError("Invalid function type")

	def match_cfunc(self, cfunc:idaapi.cfunc_t):
		"""Match schemes in decompiled function."""
		tree_processor = TreeProcessor(cfunc)
		ast_tree = cfunc.body

		schemes = [s for s in self.schemes.values() if not s.is_readonly]
		self.match_ast_tree(tree_processor, ast_tree, schemes)

		schemes = [s for s in self.schemes.values() if s.is_readonly]
		self.match_ast_tree(tree_processor, ast_tree, schemes)

	def match_ast_tree(self, tree_processor: TreeProcessor, ast_tree, schemes:list[Scheme]):
		while True:
			contexts = [PatternContext(tree_processor) for _ in schemes]
			for i, scheme in enumerate(schemes):
				scheme.on_tree_iteration_start(contexts[i])

			is_tree_modified = False
			for subitem in tree_processor.iterate_subitems(ast_tree):
				is_tree_modified = self.check_schemes(tree_processor, subitem)
				if is_tree_modified:
					break

			if is_tree_modified:
				continue

			for i, scheme in enumerate(schemes):
				scheme.on_tree_iteration_end(contexts[i])
			break

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

	def check_scheme(self, scheme: Scheme, item: idaapi.citem_t, item_ctx: PatternContext) -> bool:
		if not runtime_settings.CATCH_DURING_MATCHING:
			return self._check_scheme(scheme, item, item_ctx)

		try:
			return self._check_scheme(scheme, item, item_ctx)
		except Exception as e:
			print('[!] Got an exception during scheme checking: %s' % e)
			return False

	def _check_scheme(self, scheme: Scheme, item: idaapi.citem_t, item_ctx: PatternContext) -> bool:
		item_ctx.cleanup()

		if not any(p.check(item, item_ctx) for p in scheme.patterns):
			return False

		is_tree_modified = scheme.on_matched_item(item, item_ctx)
		if not isinstance(is_tree_modified, bool):
			raise TypeError("Handler returned invalid return type, should be bool")

		return is_tree_modified

	def finalize_item_context(self, ctx: PatternContext) -> bool:
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

	def get_scheme(self, scheme_name: str) -> Scheme|None:
		return self.schemes.get(scheme_name)

	def add_scheme(self, name:str, scheme:Scheme):
		self.schemes[name] = scheme

	def remove_scheme(self, scheme_name: str):
		self.schemes.pop(scheme_name, None)