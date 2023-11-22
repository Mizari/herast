from herapi import *


class StringDtorScheme(Scheme):
	def __init__(self):
		"""
		pattern of a combination of the forms:
		if ( v16.capacity >= 0x10)
		{
			v12 = *(void **)v16.str_or_ptr;
			if ( (unsigned __int64)(v16.capacity + 1) >= 0x1000 )
			{

			}
			j_j_free(v12);
		}
		or
		if ( v16 >= 0x10)
		{
			v12 = *(void **)v15;
			if ( (unsigned __int64)(v16 + 1) >= 0x1000 )
			{

			}
			j_j_free(v15);
		}
		how destruction of a string inline usually happens
		"""
		pattern = IfPat(
					UgePat(
						OrPat(
							VarPat(),
							MemrefPat(
								VarPat()
							),
						),
						NumPat(0x10)
					),
					BlockPat(
						AsgInsnPat(
							VarPat(bind_name="free_var"),
							OrPat(
								PtrPat(
									MemrefPat(
										VarPat(bind_name="str_as_str")
									)
								),
								PtrPat(
									VarPat(bind_name="str_as_str")
								),
								VarPat(bind_name="reg_str"),
								skip_casts=True
							)
						),
						IfPat(
							UgePat(
								OrPat(
									AddPat(
										VarPat(),
										NumPat(1)
									),
									AddPat(
										MemrefPat(
											VarPat()
										),
										NumPat(1)
									),
									skip_casts=True
								),
								NumPat(0x1000),
							),
						),
						CallInsnPat(
							AnyPat(),
							OrPat(
								VarPat(bind_name="free_var"),
								VarPat(bind_name="str_as_str")
							),
						)
					)
				)
		super().__init__(pattern)

	def on_matched_item(self, item, ctx: MatchContext):
		str_as_str = ctx.get_var("str_as_str")
		str_as_var = ctx.get_var("str_as_var")
		var = None
		if str_as_str is None:
			if str_as_var is None:
				return False
			else:
				var = str_as_var
		else:
			var = str_as_str

		new_item = make_call_helper_instr("string_dtor", var)
		ctx.modify_instr(item, new_item)
		return False


register_storage_scheme("string_dtor", StringDtorScheme())
