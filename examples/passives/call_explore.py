from __future__ import annotations
from herapi import *

test_pattern = CallInsnPat('_objc_release', ignore_arguments=True)


class ItemRemovalScheme(Scheme):
	def on_matched_item(self, item, ctx: MatchContext) -> ASTPatch|None:
		return ASTPatch(item, None)


register_storage_scheme("remove_objc_release", ItemRemovalScheme(test_pattern))