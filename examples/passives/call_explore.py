from herapi import *

test_pattern = CallInsnPat('_objc_release', ignore_arguments=True)

class ItemRemovalScheme(Scheme):
	def on_matched_item(self, item, ctx: MatchContext) -> bool:
		ctx.add_patch(item, None)
		return False

register_storage_scheme("remove_objc_release", ItemRemovalScheme(test_pattern))