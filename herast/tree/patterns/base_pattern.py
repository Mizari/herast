import idaapi
import typing
import traceback
from herast.tree.ast_context import ASTContext

class BasePat:
	"""Base class for all patterns."""
	op = None

	def __init__(self, debug=False, debug_msg=None, debug_trace_depth=0, check_op: typing.Optional[int] = None):
		"""
		:param debug: should provide debug information during matching
		:param debug_msg: additional message to print on debug
		:param debug_trace_depth: additional trace information on debug
		:param check_op: what item type to check. skips this check if None
		"""
		self.check_op = check_op
		self.debug = debug
		self.debug_msg = debug_msg
		self.debug_trace_depth = debug_trace_depth
	
	def _assert(self, cond, msg=""):
		assert cond, "%s: %s" % (self.__class__.__name__, msg)
	
	def _raise(self, msg):
		raise "%s: %s" % (self.__class__.__name__, msg)

	def check(self, item, ctx: ASTContext, *args, **kwargs) -> bool:
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
	def base_check(func):
		"""Decorator for child classes instead of inheritance, since
		before and after calls are needed.
		"""
		def __perform_base_check(self:BasePat, item, *args, **kwargs):
			if item is None:
				return False

			if self.check_op is not None and item.op != self.check_op:
				return False

			rv = func(self, item, *args, **kwargs)

			if self.debug:
				if self.debug_msg:
					print("Debug: value =", rv, ",", self.debug_msg)
				else:
					print("Debug: value =", rv)

				if self.debug_trace_depth != 0:
					print('Debug calltrace, address of item: %#x (%s)' % (item.ea, item.opname))
					print('---------------------------------')
					for i in traceback.format_stack()[:self.debug_trace_depth]:
						print(i)
					print('---------------------------------')
			return rv
		return __perform_base_check

	@property
	def children(self):
		raise NotImplementedError("An abstract class doesn't have any children")