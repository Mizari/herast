import idaapi
from herast.tree.pattern_context import PatternContext
import herast.tree.consts as consts

class BasePattern:
	op = None

	def __init__(self, debug=False, skip_casts=True, check_op=None):
		self.check_op = check_op
		self.debug = debug
		self.skip_casts = skip_casts
	
	def _assert(self, cond, msg=""):
		assert cond, "%s: %s" % (self.__class__.__name__, msg)
	
	def _raise(self, msg):
		raise "%s: %s" % (self.__class__.__name__, msg)

	def check(self, item, ctx: PatternContext, *args, **kwargs) -> bool:
		raise NotImplementedError("This is an abstract class")

	@classmethod
	def get_opname(cls):
		return consts.op2str.get(cls.op, None)

	@staticmethod
	def parent_check(func):
		def __perform_parent_check(self, item, *args, **kwargs):
			if item is None:
				return False

			if self.skip_casts and item.op == idaapi.cot_cast:
				item = item.x

			if self.check_op is not None and item.op != self.check_op:
				return False

			return func(self, item, *args, **kwargs)
		return __perform_parent_check

	@property
	def children(self):
		raise NotImplementedError("An abstract class doesn't have any children")

