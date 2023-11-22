from __future__ import annotations

import idaapi
import idc

import herast.tree.utils as utils
from herast.tree.ast_context import ASTContext
from herast.tree.match_context import MatchContext
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
		ast_tree = cfunc.body
		ast_ctx = ASTContext(cfunc)

		schemes = [s for s in self.schemes.values() if not s.is_readonly]
		self.match_ast_tree(ast_tree, ast_ctx, schemes)

		schemes = [s for s in self.schemes.values() if s.is_readonly]
		self.match_ast_tree(ast_tree, ast_ctx, schemes)

	def match_ast_tree(self, ast_tree:idaapi.citem_t, ast_ctx: ASTContext, schemes:list[Scheme]):
		tree_proc = TreeProcessor(ast_ctx.cfunc)
		while True:
			contexts = [ASTContext(ast_ctx) for _ in schemes]
			for i, scheme in enumerate(schemes):
				scheme.on_tree_iteration_start()

			is_tree_modified = False
			for subitem in tree_proc.iterate_subitems(ast_tree):
				is_tree_modified = self.check_schemes(subitem, ast_ctx)
				if is_tree_modified:
					break

			if is_tree_modified:
				continue

			for i, scheme in enumerate(schemes):
				scheme.on_tree_iteration_end()
			break

	def check_schemes(self, item:idaapi.citem_t, ast_ctx: ASTContext) -> bool:
		"""Match item in schemes.

		:param tree_processor:
		:param item: AST item
		:return: is item modified/removed?
		"""
		for scheme in self.schemes.values():
			if self.check_scheme(scheme, item, ast_ctx):
				return True

		return False

	def check_scheme(self, scheme: Scheme, item: idaapi.citem_t, ast_ctx: ASTContext) -> bool:
		if not runtime_settings.CATCH_DURING_MATCHING:
			return self._check_scheme(scheme, item, ast_ctx)

		try:
			return self._check_scheme(scheme, item, ast_ctx)
		except Exception as e:
			print('[!] Got an exception during scheme checking: %s' % e)
			return False

	def _check_scheme(self, scheme: Scheme, item: idaapi.citem_t, ast_ctx: ASTContext) -> bool:
		for pat in scheme.patterns:
			mctx = MatchContext(ast_ctx.cfunc, pat)
			# check that pattern matches AST item
			if not pat.check(item, mctx):
				continue

			# handle user's scheme callback
			is_tree_modified = scheme.on_matched_item(item, mctx)
			if not isinstance(is_tree_modified, bool):
				raise TypeError("Handler returned invalid return type, should be bool")
			if not is_tree_modified:
				continue

			# try to modify AST
			if self.finalize_item_context(mctx):
				return True

		return False

	def finalize_item_context(self, ctx:MatchContext) -> bool:
		tree_proc = TreeProcessor(ctx.cfunc)
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