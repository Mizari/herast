from schemes.base_scheme import Scheme


class MPScheme(Scheme):
	def __init__(self, patterns) -> None:
		self.patterns = patterns
		super().__init__()

	def get_patterns(self):
		return list(self.patterns)