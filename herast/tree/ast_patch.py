


class ASTPatch:
	def __init__(self, item, new_item):
		self.item = item
		self.new_item = new_item

	@classmethod
	def remove_item(cls, item):
		return cls(item, None)

	@classmethod
	def replace_item(cls, item, new_item):
		return cls(item, new_item)