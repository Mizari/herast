import idaapi

from herast.tree.patterns.base_pattern import BasePattern
from herast.tree.pattern_context import PatternContext


# any pattern
class AnyPat(BasePattern):
	op = -1

	def __init__(self, may_be_none=True):
		self.may_be_none = may_be_none

	def check(self, item, ctx: PatternContext) -> bool:
		return item is not None or self.may_be_none

	@property
	def children(self):
		return ()

class OrPat(BasePattern):
	op = -1

	def __init__(self, *pats):
		if len(pats) <= 1:
			print("[*] WARNING: OrPat expects at least two patterns")
		self.pats = tuple(pats)

	def check(self, item, ctx: PatternContext) -> bool:
		for p in self.pats:
			if p.check(item, ctx):
				return True
		
		return False

	@property
	def children(self):
		return self.pats

class AndPat(BasePattern):
	op = -1

	def __init__(self, *pats):
		self._assert(len(pats) > 1, "Passing one or less patterns to AndPat is useless")
		self.pats = tuple(pats)

	def check(self, item, ctx: PatternContext) -> bool:
		for p in self.pats:
			if not p.check(item, ctx):
				return False

		return True

	@property
	def children(self):
		return self.pats

class SkipCasts(BasePattern):
	op = -1

	def __init__(self, pat):
		self.pat = pat

	def check(self, item, ctx: PatternContext) -> bool:
		while item.op == idaapi.cot_cast:
			item = item.x
		
		return self.pat.check(item, ctx)

	@property
	def children(self):
		return self.pat

class BindItem(BasePattern):
	op = -1

	def __init__(self, name, pat=None):
		self.pat = pat or AnyPat()
		self.name = name

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
	op = idaapi.cot_var

	def __init__(self, name):
		self.name = name

	@BasePattern.initial_check
	def check(self, expr, ctx: PatternContext) -> bool:
		if ctx.has_var(self.name):
			return ctx.get_var(self.name).v.idx == expr.v.idx
		else:
			ctx.save_var(self.name, expr)
			return True


class DeepExpr(BasePattern):
	op = -1

	def __init__(self, pat, bind_name=None):
		self.pat = pat
		self.found = False
		self.bind_name = bind_name

	def check(self, expr, ctx: PatternContext) -> bool:
		self.found = False
		def processing_callback(tree_proc, item):
			if not self.found:
				if self.pat.check(item, ctx):
					if self.bind_name is not None:
						ctx.save_expr(self.bind_name, item)
					self.found = True
			return False
		ctx.tree_proc.process_all_items(expr, processing_callback)

		return self.found


class LabeledInstruction(BasePattern):
	op = -1
	def __init__(self):
		return

	def check(self, item, ctx: PatternContext) -> bool:
		lbl = item.label_num
		if lbl == -1:
			return False
		return True


class ItemsCollector:
	op = -1
	def __init__(self, pat):
		self.pat = pat
		self.collected_items = []

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
	op = -1
	def __init__(self, pat):
		self.pat = pat

	def check(self, item, ctx: PatternContext) -> bool:
		if not self.pat.check(item, ctx):
			return False

		ctx.modify_instr(item, None)
		return True


import traceback
# For debug purposes
class DebugPattern(BasePattern):
	op = -1
	call_depth = 6

	def __init__(self, return_value=False):
		self.return_value = return_value

	def check(self, item, ctx: PatternContext) -> bool:
		print('Debug calltrace, address of item: %#x (%s)' % (item.ea, item.opname))
		print('---------------------------------')
		for i in traceback.format_stack()[:self.call_depth]:
			print(i)
		print('---------------------------------')

		return self.return_value
		

# useful pattern to determine where big and complex pattern went wrong
class DebugWrapper(BasePattern):
	op = -1
	def __init__(self, pat, msg=None):
		self.pat = pat
		self.msg = msg

	def check(self, item, ctx: PatternContext) -> bool:
		rv = self.pat.check(item, ctx)
		if self.msg is None:
			print("Debug pattern rv:", rv)
		else:
			print("Debug pattern", self.msg, "rv:", rv)
		return rv