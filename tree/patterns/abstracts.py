import idaapi

idaapi.require('tree.processing')
idaapi.require('tree.consts')

import tree.consts as consts
from tree.processing import TreeProcessor

# [TODO]: for some reason i've thought that not-recursive check of children may be useful, but forget how can i use it
# [TODO]: so should think about it and also think about splitting AbstractPattern to BasePattern(for "real" patterns with `op` == cot_*|cit_*)
# [TODO]: and BaseAbstractPattern(for abstract patterns, which doesn't have any `op` and performs checking in other way)

# [TODO]: add stripping of cot_cast's before passing node to actual pattern-object, we can call super(self).__init__ with some kwargs
# [TODO]: like skip_casts=False|True and add skipping in __perform_inital_check
class AbstractPattern:
	op = None

	def __init__(self):
		pass
	
	def _assert(self, cond, msg=""):
		assert cond, "%s: %s" % (self.__class__.__name__, msg)
	
	def _raise(self, msg):
		raise "%s: %s" % (self.__class__.__name__, msg)

	def check(self, item, ctx, *args, **kwargs):
		raise NotImplementedError("This is an abstract class")

	@classmethod
	def get_opname(cls):
		return consts.op2str.get(cls.op, None)

	@staticmethod
	def initial_check(func):
		def __perform_initial_check(self, item, *args, **kwargs):
			if item is None or (item.op != self.op and self.op is not None):
				return False
			else:
				return func(self, item, *args, **kwargs)
		return __perform_initial_check

	@property
	def children(self):
		raise NotImplementedError("An abstract class doesn't have any children")



# any pattern
class AnyPat(AbstractPattern):
	op = -1

	def __init__(self, may_be_none=True):
		self.may_be_none = may_be_none

	def check(self, item, ctx):
		return item is not None or self.may_be_none

	@property
	def children(self):
		return ()

# sequence of instructions
class SeqPat(AbstractPattern):
	op = -1

	def __init__(self, pats):
		if type(pats) is not tuple and type(pats) is not list:
			pats = (pats, )

		self.seq = pats
		self.length = len(pats)

	def check(self, instruction, ctx):
		parent = ctx.current_function.body.find_parent_of(instruction)

		# There is can be no sequence unless its parent is a cblock instruction
		if parent is None or parent.op != idaapi.cit_block:
			return False

		container = parent.cinsn.cblock
		start_from = container.index(instruction)
		if start_from + self.length > len(container):
			return False

		for i in range(self.length):
			if not self.seq[i].check(container[start_from + i], ctx):
				return False
		return True

	@property
	def children(self):
		return tuple(self.pats)

class OrPat(AbstractPattern):
	op = -1

	def __init__(self, *pats):
		self._assert(len(pats) > 1, "Passing one or less patterns to OrPat is useless")
		self.pats = tuple(pats)
	
	def check(self, item, ctx):
		for p in self.pats:
			if p.check(item, ctx):
				return True
		
		return False

	@property
	def children(self):
		return self.pats

class SkipCasts(AbstractPattern):
	op = -1

	def __init__(self, pat):
		self.pat = pat

	def check(self, item, ctx):
		while item.op == idaapi.cot_cast:
			item = item.x
		
		return self.pat.check(item, ctx)

	@property
	def children(self):
		return self.pat

class BindExpr(AbstractPattern):
	op = -1

	def __init__(self, name, pat=None):
		self.pat = pat or AnyPat()
		self.name = name
	
	def check(self, expr, ctx):
		if self.pat.check(expr, ctx):
			ctx.save_expr(self.name, expr)
			return True
		return False


class VarBind(AbstractPattern):
	op = idaapi.cot_var

	def __init__(self, name):
		self.name = name

	@AbstractPattern.initial_check
	def check(self, expr, ctx):
		if expr.op == idaapi.cot_var:
			if ctx.has_var(self.name):
				return ctx.get_var(self.name).idx == expr.v.idx
			else:
				ctx.save_var(self.name, expr.v.idx)
				return True

		return False


class DeepExpr(AbstractPattern):
	op = -1

	def __init__(self, pat):
		self.pat = pat

	def check(self, expr, ctx):
		m = FakeMatcher(self.pat, ctx)
		t = TreeProcessor(expr, m, need_expression_traversal=True)
		t.process_tree()

		return m.found


class FakeMatcher:
	def __init__(self, pat, ctx):
		self.pat = pat
		self.ctx = ctx
		self.found = False

	def check_patterns(self, item):
		if not self.found:
			if self.pat.check(item, self.ctx):
				self.found = True

		return False


import traceback, tree.consts
# For debug purposes
class DebugPattern(AbstractPattern):
	op = -1
	call_depth = 6

	def __init__(self, return_value=False):
		self.return_value = return_value

	def check(self, item, ctx):
		print('Debug calltrace, address of item: %#x (%s)' % (item.ea, tree.consts.op2str[item.op]))
		print('---------------------------------')
		for i in traceback.format_stack()[:self.call_depth]:
			print(i)
		print('---------------------------------')

		return self.return_value
		
