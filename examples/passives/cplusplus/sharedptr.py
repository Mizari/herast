from herapi import *

class HelperReplacer(Scheme):
	"""
		this scheme either removes or replaces one item
		with helper function of a given name without arguments
	"""
	def __init__(self, pattern, helper_name, should_remove=False):
		self.helper_name = helper_name
		self.should_remove = should_remove
		super().__init__(pattern)

	def on_matched_item(self, item, ctx: MatchContext):
		if self.should_remove:
			new_item = None
		else:
			new_item = make_call_helper_instr(self.helper_name)
		ctx.modify_instr(item, new_item)
		return False

"""
	A rather complex pattern representing releasing of C++'s sharedptr
	incomplete for now, but still sufficient for matching purposes
	if (...) {              # outer IF
		if (...) {          # inner IF0
			...;
		} else {
			...;
			...;
		}
		if (...) {          # inner IF1
			...;
			if (...) {      # inner IF2
				...;
			} else {
				...;
				...;
			}
			if (...) {      # inner IF3
				...;
			}
		}
	}
"""
release_pattern = \
	IfPat(                                 # outer IF
		AnyPat(),                          # if memptr
		BlockPat(
			IfPat(                         # inner IF0
				AnyPat(),                  # if pthread_cancel
				ExprInsPat(),              # asg interlocked_xchg(any, 0xffffffff)
				BlockPat(
					ExprInsPat(),          # var asg
					ExprInsPat(),          # memptr = var - 1
				),
			),
			IfPat(                         # inner IF1
				AnyPat(),                  # if decrement result == 1
				BlockPat(
					ExprInsPat(),          # call(_M_dispose) of *varmemptr + 16
					IfPat(                 # inner IF2
						AnyPat(),          # if pthread_cancel
						ExprInsPat(),      # asg interlocked_xchg (any, 0xfffffff)
						BlockPat(
							ExprInsPat(),  # var asg
							ExprInsPat(),  # memptr = var - 1
						),
					),
					IfPat(                 # inner IF3
						AnyPat(),          # if decrement result == 1
						ExprInsPat(),      # call(_M_destroy) of *varmemptr + 24
					),
				),
			),
		),
	)

"""
	this patterns looks for two instructions
	first one will later be replaced/removed in HelperReplacer
	second one will be deleted via Remove Pattern
"""
release_pattern = SeqPat(AsgInsnPat(VarPat(), AnyPat()), RemovePat(release_pattern))
register_storage_scheme("shptr_release", HelperReplacer(release_pattern, "__sharedptr::release"))

def cond_insn(pat):
	"""
		try to match first on IfPat(Any, pat), then on pat
	"""
	return OrPat(IfPat(AnyPat(), pat), pat)


"""
	increment_pattern is for removing/replacing this code:
		if (pthread_cancel) {
			_InterlockedAdd(...);
		}
	OR
		if (...) {
			if (pthread_cancel) {
				_InterlockedAdd(...);
			}
		}
"""
increment_pattern = cond_insn(IfPat(
	ObjPat("pthread_cancel"),
	CallInsnPat(HelperPat("_InterlockedAdd"), skip_missing=True),
	ExprInsPat(),
))

register_storage_scheme("shptr_inc", HelperReplacer(increment_pattern, "__sharedptr::increment"))



class ItemRemovalScheme(Scheme):
	def on_matched_item(self, item, ctx: MatchContext) -> bool:
		ctx.modify_instr(item, None)
		return False

"""
	std_release_pattern is for removing this code:
		std::_Sp_counted_base::_M_release(...);
	OR
		if (...) {
			std::_Sp_counted_base::_M_release(...);
		}
"""
std_release_pattern = cond_insn(CallInsnPat(
									"std::_Sp_counted_base::_M_release",
									ignore_arguments=True
								))
register_storage_scheme("shptr_release_remover", ItemRemovalScheme(RemovePat(std_release_pattern)))