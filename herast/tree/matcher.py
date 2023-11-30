from __future__ import annotations

import idaapi
import idc

import herast.tree.utils as utils
from herast.tree.ast_context import ASTContext
from herast.tree.ast_patch import ASTPatch
from herast.tree.match_context import MatchContext
from herast.tree.ast_processor import ASTProcessor
from herast.tree.scheme import Scheme
from herast.settings import runtime_settings


class Matcher:
	def __init__(self, *schemes):
		self.schemes : dict[str, Scheme] = {"scheme" + str(i): s for i, s in enumerate(schemes)}

	def get_scheme(self, scheme_name: str) -> Scheme|None:
		return self.schemes.get(scheme_name)

	def add_scheme(self, name:str, scheme:Scheme):
		self.schemes[name] = scheme

	def remove_scheme(self, scheme_name: str):
		self.schemes.pop(scheme_name, None)

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
		for scheme in schemes:
			scheme.on_tree_iteration_start()

		ast_proc = ASTProcessor(ast_tree)
		while (subitem := ast_proc.pop_current()) is not None:
			if (ast_patch := self.check_schemes(subitem, ast_ctx, schemes)) is None:
				continue

			ast_proc.apply_patch(ast_patch, ast_ctx)
			# check if patch restarted iteration
			if ast_proc.is_iteration_started():
				for scheme in schemes:
					scheme.on_tree_iteration_start()

		for scheme in schemes:
			scheme.on_tree_iteration_end()

	def check_schemes(self, item:idaapi.citem_t, ast_ctx: ASTContext, schemes:list[Scheme]) -> ASTPatch|None:
		"""Match item in schemes.

		:param tree_processor:
		:param item: AST item
		:return: is item modified/removed?
		"""
		for scheme in schemes:
			ast_patch = self.check_scheme(scheme, item, ast_ctx)
			if ast_patch is not None:
				return ast_patch

		return None

	def check_scheme(self, scheme: Scheme, item: idaapi.citem_t, ast_ctx: ASTContext) -> ASTPatch|None:
		if not runtime_settings.CATCH_DURING_MATCHING:
			return self._check_scheme(scheme, item, ast_ctx)

		try:
			return self._check_scheme(scheme, item, ast_ctx)
		except Exception as e:
			print('[!] Got an exception during scheme checking: %s' % e)
			return None

	def _check_scheme(self, scheme: Scheme, item: idaapi.citem_t, ast_ctx: ASTContext) -> ASTPatch|None:
		for pat in scheme.patterns:
			mctx = MatchContext(ast_ctx.cfunc, pat)
			# check that pattern matches AST item
			if not pat.check(item, mctx):
				continue

			# handle user's scheme callback
			ast_patch = scheme.on_matched_item(item, mctx)
			if ast_patch is None:
				continue

			# schemes handlers are written by users, need to validate return value
			if not isinstance(ast_patch, ASTPatch):
				raise TypeError("Handler returned invalid return type, should be ASTPatch or None")

			return ast_patch

		return None