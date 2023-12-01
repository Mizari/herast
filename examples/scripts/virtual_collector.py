from __future__ import annotations
from herapi import *


class VirtualCollector(Scheme):
	def __init__(self, struct_type=None, offset=None):
		pattern = AsgPat(StructFieldAccessPat(struct_type, offset), AnyPat())
		super().__init__(pattern, scheme_type=Scheme.SchemeType.READONLY)
		self.collection = []

	def on_matched_item(self, item, ctx:MatchContext) -> ASTPatch|None:
		func_ea = ctx.func_addr
		struct_type = item.x.x.type.get_pointed_object()
		offset = item.x.m
		value = item.y
		self.collection.append((func_ea, struct_type, offset, value))
		return None

def collect_virtual_properties(*functions, struct_type=None, offset=None):
	scheme = VirtualCollector(struct_type, offset)
	match(scheme, *functions)

	for func_ea, struct_type, offset, value in scheme.collection:
		yield func_ea, struct_type, offset, value