from herapi import *

test_pattern = CallInsnPat('_objc_release', ignore_arguments=True)

class ItemRemovalScheme(Scheme):
	def on_matched_item(self, item, ctx: PatternContext) -> bool:
		ctx.modify_instr(item, None)
		return False

register_storage_scheme(ItemRemovalScheme("remove_objc_release", test_pattern))