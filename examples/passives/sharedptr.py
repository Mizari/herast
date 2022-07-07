from herapi import *

class HelperReplacer(SPScheme):
	def __init__(self, name, pattern, helper_name, should_remove=False):
		self.helper_name = helper_name
		self.should_remove = should_remove
		super().__init__(name, pattern)

	def on_matched_item(self, item, ctx: PatternContext):
		if self.should_remove:
			new_item = None
		else:
			new_item = make_call_helper_instr(self.helper_name)
		ctx.modify_instr(item, new_item)
		return False


release_pattern = SeqPat(
	ExprInsPat(),  # var = memptr
	RemovePattern(IfPat(
		AnyPat(),  # if memptr
		SeqPat(
			IfPat(
				AnyPat(),  # if pthread_cancel
				ExprInsPat(),  # asg interlocked_xchg(any, 0xffffffff)
				SeqPat(
					ExprInsPat(),  # var asg
					ExprInsPat(),  # memptr = var - 1
				),
			),
			IfPat(
				AnyPat(), # if decrement result == 1
				SeqPat(
					ExprInsPat(),  # call(_M_dispose) of *varmemptr + 16
					IfPat(
						AnyPat(),  # if pthread_cancel
						ExprInsPat(),  # asg interlocked_xchg (any, 0xfffffff)
						SeqPat(
							ExprInsPat(),  # var asg
							ExprInsPat(),  # memptr = var - 1
						),
					),
					IfPat(
						AnyPat(),  # if decrement result == 1
						ExprInsPat(), # call(_M_destroy) of *varmemptr + 24
					),
				),
			),
		),
	)),
)

register_storage_scheme(HelperReplacer("shptr_release", release_pattern, "__sharedptr::release"))


increment_pattern = IfPat(
	ObjPat("pthread_cancel"),
	CallInsnPat(HelperPat("_InterlockedAdd"), skip_missing=True),
	ExprInsPat(),
)

increment_pattern = OrPat(
	IfPat(AnyPat(), increment_pattern),
	increment_pattern,
)
register_storage_scheme(HelperReplacer("shptr_inc", increment_pattern, "__sharedptr::increment"))


fname = "std::_Sp_counted_base::_M_release"
std_release_pattern = OrPat(
	IfPat(AnyPat(), CallInsnPat(fname, ignore_arguments=True)),
	CallInsnPat(fname, ignore_arguments=True),
)

register_storage_scheme(ItemRemovalScheme("shptr_release_remover", RemovePattern(std_release_pattern)))