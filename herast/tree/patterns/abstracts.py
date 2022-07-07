import idaapi
import typing

from herast.tree.patterns.base_pattern import BasePattern
from herast.tree.pattern_context import PatternContext


# any pattern
class AnyPat(BasePattern):
	def __init__(self, may_be_none=True, **kwargs):
		super().__init__(**kwargs)
		self.may_be_none = may_be_none

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		return item is not None or self.may_be_none

	@property
	def children(self):
		return ()

class OrPat(BasePattern):
	def __init__(self, *pats: BasePattern, **kwargs):
		super().__init__(**kwargs)
		if len(pats) <= 1:
			print("[*] WARNING: OrPat expects at least two patterns")
		self.pats = tuple(pats)

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		for p in self.pats:
			if p.check(item, ctx):
				return True
		
		return False

	@property
	def children(self):
		return self.pats

class AndPat(BasePattern):
	def __init__(self, *pats: BasePattern, **kwargs):
		super().__init__(**kwargs)
		self._assert(len(pats) > 1, "Passing one or less patterns to AndPat is useless")
		self.pats = tuple(pats)

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		for p in self.pats:
			if not p.check(item, ctx):
				return False

		return True

	@property
	def children(self):
		return self.pats

class SkipCasts(BasePattern):
	def __init__(self, pat: BasePattern, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		while item.op == idaapi.cot_cast:
			item = item.x
		
		return self.pat.check(item, ctx)

	@property
	def children(self):
		return self.pat

class BindItem(BasePattern):
	def __init__(self, name: str, pat: typing.Optional[BasePattern] = None, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat or AnyPat()
		self.name = name

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		if self.pat.check(item, ctx):
			current_expr = ctx.get_expr(self.name)
			if current_expr is None:
				ctx.save_expr(self.name, item)
				return True
			else:
				return item.equal_effect(current_expr)
		return False


class VarBind(BasePattern):
	def __init__(self, name: str, **kwargs):
		super().__init__(**kwargs)
		self.name = name

	@BasePattern.parent_check
	def check(self, expr, ctx: PatternContext) -> bool:
		if expr.op != idaapi.cot_var:
			return False

		if ctx.has_var(self.name):
			return ctx.get_var(self.name).v.idx == expr.v.idx
		else:
			ctx.save_var(self.name, expr)
			return True


class DeepExpr(BasePattern):
	def __init__(self, pat: BasePattern, bind_name=None, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat
		self.bind_name = bind_name

	@BasePattern.parent_check
	def check(self, expr, ctx: PatternContext) -> bool:
		for item in ctx.tree_proc.iterate_subitems(expr):
			if not self.pat.check(item, ctx):
				continue
			if self.bind_name is not None:
				ctx.save_expr(self.bind_name, item)
			return True
		return False


class LabeledInstruction(BasePattern):
	def __init__(self, **kwargs):
		super().__init__(**kwargs)

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		lbl = item.label_num
		if lbl == -1:
			return False
		return True


class ItemsCollector:
	def __init__(self, pat: BasePattern):
		self.pat = pat
		self.collected_items : typing.List = []

	def check_pattern(self, tree_proc, item):
		ctx = PatternContext(tree_proc)
		try:
			if self.pat.check(item, ctx):
				self.collected_items.append(item)
		except Exception as e:
			print("[!] exception happend during collecting pattern in item :%s" % e)

		return False

	def collect_items(self, tree_proc, item):
		self.collected_items.clear()
		def processing_callback(tree_proc, item):
			return self.check_pattern(tree_proc, item)
		tree_proc.process_all_items(item, processing_callback)
		return self.collected_items

class RemovePattern(BasePattern):
	def __init__(self, pat: BasePattern, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		if not self.pat.check(item, ctx):
			return False

		ctx.modify_instr(item, None)
		return True


# For debug purposes
class DebugPattern(BasePattern):
	call_depth = 6

	def __init__(self, return_value=False, **kwargs):
		super().__init__(**kwargs)
		self.return_value = return_value

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		print('Debug calltrace, address of item: %#x (%s)' % (item.ea, item.opname))
		print('---------------------------------')
		import traceback
		for i in traceback.format_stack()[:self.call_depth]:
			print(i)
		print('---------------------------------')

		return self.return_value
		

# useful pattern to determine where big and complex pattern went wrong
class DebugWrapper(BasePattern):
	def __init__(self, pat: BasePattern, msg=None, **kwargs):
		super().__init__(**kwargs)
		self.pat = pat
		self.msg = msg

	@BasePattern.parent_check
	def check(self, item, ctx: PatternContext) -> bool:
		rv = self.pat.check(item, ctx)
		if self.msg is None:
			print("Debug pattern rv:", rv)
		else:
			print("Debug pattern", self.msg, "rv:", rv)
		return rv