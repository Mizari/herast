from herast.schemes.base_scheme import Scheme


class MPScheme(Scheme):
	"""A scheme with multiple patterns"""
	def __init__(self, name: str, patterns) -> None:
		self.patterns = patterns
		super().__init__(name)

	def get_patterns(self):
		return list(self.patterns)