import idaapi

idaapi.require('tree.patterns.abstracts')

from tree.patterns.abstracts import SeqPat, BindExpr, VarBind

# [TODO]: mb somehow it should have architecture when patterns can provide some more feedback to matcher, not only True/False
# it can be useful to not traverse every expresion for every pattern-chain, and do it only with a particular-ones
 
class Matcher:
	def __init__(self, processed_function):
		self.function = processed_function
		self.patterns = list()

	def check_patterns(self, item) -> bool:
		for pattern, handler, ctx in self.patterns:
			try:
				ctx.cleanup()
			except Exception as e:
				print('[!] Got an exception during context cleanup: %s' % e)

			try:
				if not pattern.check(item, ctx):
					continue
			except Exception as e:
				print('[!] Got an exception during pattern matching: %s' % e)

			try:
				rv = handler(item, ctx)
				if not isinstance(rv, bool):
					raise Exception("Handler return invalid return type, should be bool")

				if rv:
					return True
			except Exception as e:
				print('[!] Got an exception during pattern handling: %s' % e)

		return False

	def insert_pattern(self, pat, handler):
		ctx = SavedContext(self.function)
		self.patterns.append((pat, handler, ctx))

	def expressions_traversal_is_needed(self):
		abstract_expression_patterns = [VarBind, BindExpr]
		
		for p, _, _ in self.patterns:
			if p.op >= 0 and p.op < idaapi.cit_empty or any((isinstance(p, abstract_class) for abstract_class in abstract_expression_patterns)):
				return True

		return False

class SavedContext:
	def __init__(self, current_function):
		self.current_function = current_function
		self.expressions = dict()
		self.variables = dict()

	def get_var(self, name):
		return self.variables.get(name, None)

	def save_var(self, name, local_variable_index):
		self.variables[name] = SavedVariable(local_variable_index)

	def has_var(self, name):
		return self.variables.get(name, None) is not None

	def get_expr(self, name):
		return self.expressions.get(name, None)

	def save_expr(self, name, expression):
		self.expressions[name] = expression

	def cleanup(self):
		self.variables.clear()
		self.expressions.clear()

class SavedVariable:
	def __init__(self, idx):
		self.idx = idx