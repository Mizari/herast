from herast.tree.pattern_context import PatternContext
import herast.tree.consts as consts

class BasePattern:
	op = None

	def __init__(self):
		pass
	
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

