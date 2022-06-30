from herapi import *

SHOULD_REMOVE = True


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

class HelperReplacer(SPScheme):
	def __init__(self, name, pattern, helper_name):
		self.helper_name = helper_name
		super().__init__(name, pattern)
	
	def on_matched_item(self, item, ctx: PatternContext):
		if SHOULD_REMOVE:
			new_item = None
		else:
			new_item = make_call_helper_instr(self.helper_name)
		ctx.modify_instr(item, new_item)
		return False

register_storage_scheme(HelperReplacer("shptr_release", release_pattern, "__sharedptr::release"))


add1 = SkipCasts(CallPat(HelperPat(helper_name="_InterlockedAdd"), skip_missing=True))

increment_pattern = IfPat(
	ObjPat("pthread_cancel"),
	ExprInsPat(add1),
	ExprInsPat(),
)

increment_pattern = OrPat(
	increment_pattern,
	IfPat(AnyPat(), increment_pattern),
)
register_storage_scheme(HelperReplacer("shptr_inc", increment_pattern, "__sharedptr::increment"))

fname = "std::_Sp_counted_base::_M_release"
std_release_pattern = ExprInsPat(SkipCasts(CallPat(fname, ignore_arguments=True)))
std_release_pattern = OrPat(
	std_release_pattern,
	IfPat(AnyPat(), std_release_pattern),
)

if SHOULD_REMOVE:
	register_storage_scheme(SPScheme("shptr_release_remover", RemovePattern(std_release_pattern)))