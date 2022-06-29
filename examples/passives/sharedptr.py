from herapi import *

SHOULD_REMOVE = True


release_pattern = SeqPat(
	ExInsPat(),  # var = memptr
	RemovePattern(IfInsPat(
		AnyPat(),  # if memptr
		SeqPat(
			IfInsPat(
				AnyPat(),  # if pthread_cancel
				ExInsPat(),  # asg interlocked_xchg(any, 0xffffffff)
				SeqPat(
					ExInsPat(),  # var asg
					ExInsPat(),  # memptr = var - 1
				),
			),
			IfInsPat(
				AnyPat(), # if decrement result == 1
				SeqPat(
					ExInsPat(),  # call(_M_dispose) of *varmemptr + 16
					IfInsPat(
						AnyPat(),  # if pthread_cancel
						ExInsPat(),  # asg interlocked_xchg (any, 0xfffffff)
						SeqPat(
							ExInsPat(),  # var asg
							ExInsPat(),  # memptr = var - 1
						),
					),
					IfInsPat(
						AnyPat(),  # if decrement result == 1
						ExInsPat(), # call(_M_destroy) of *varmemptr + 24
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


add1 = SkipCasts(CallExprPat(HelperExprPat(helper_name="_InterlockedAdd"), skip_missing=True))

increment_pattern = IfInsPat(
	ObjPat("pthread_cancel"),
	ExInsPat(add1),
	ExInsPat(),
)

increment_pattern = OrPat(
	increment_pattern,
	IfInsPat(AnyPat(), increment_pattern),
)
register_storage_scheme(HelperReplacer("shptr_inc", increment_pattern, "__sharedptr::increment"))

fname = "std::_Sp_counted_base::_M_release"
std_release_pattern = ExInsPat(SkipCasts(CallExprPat(fname, ignore_arguments=True)))
std_release_pattern = OrPat(
	std_release_pattern,
	IfInsPat(AnyPat(), std_release_pattern),
)

if SHOULD_REMOVE:
	register_storage_scheme(SPScheme("shptr_release_remover", RemovePattern(std_release_pattern)))