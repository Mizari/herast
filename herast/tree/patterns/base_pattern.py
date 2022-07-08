import idaapi
import typing
from herast.tree.pattern_context import PatternContext

class BasePattern:
	"""Base class for all patterns."""
	op = None

	def __init__(self, debug=False, skip_casts=True, check_op: typing.Optional[int] = None):
		"""
		:param debug: should provide debug information during matching
		:param skip_casts: should skip type casting
		:param check_op: what item type to check. skips this check if None
		"""
		self.check_op = check_op
		self.debug = debug
		self.skip_casts = skip_casts
	
	def _assert(self, cond, msg=""):
		assert cond, "%s: %s" % (self.__class__.__name__, msg)
	
	def _raise(self, msg):
		raise "%s: %s" % (self.__class__.__name__, msg)

	def check(self, item, ctx: PatternContext, *args, **kwargs) -> bool:
		"""Base matching operation.
	
		:param item: AST item
		:param ctx: matching context
		"""
		raise NotImplementedError("This is an abstract class")

	@classmethod
	def get_opname(cls):
		import herast.tree.consts as consts
		return consts.op2str.get(cls.op, None)

	@staticmethod
	def parent_check(func):
		"""Decorator for child classes instead of inheritance, since
		before and after calls are needed.
		"""
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

