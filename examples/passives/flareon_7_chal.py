import struct
from herapi import *


pattern = SeqPat(
				# ExInsPat(AsgPat(BindExpr('gobj', ObjPat()), SkipCasts(CallPat(ObjPat(name='j__malloc_base'), ignore_arguments=True)))),
				# ExInsPat(AnyPat()),
				ExprInsPat(AsgPat(AnyPat(), BindItemPat('num0', AnyPat()))),
				ExprInsPat(AsgPat(AnyPat(), BindItemPat('num1', AnyPat()))),
				ExprInsPat(AsgPat(AnyPat(), BindItemPat('num2', AnyPat()))),
				ExprInsPat(AsgPat(AnyPat(), BindItemPat('num3', AnyPat()))),
				# ExInsPat(AsgPat(AnyPat(), BindExpr('num4', AnyPat()))),
				# ExInsPat(AsgPat(AnyPat(), BindExpr('num5', AnyPat()))),
				# ExInsPat(AsgPat(AnyPat(), BindExpr('num6', AnyPat()))),
				# ExInsPat(AsgPat(AnyPat(), BindExpr('num7', AnyPat()))),
				ForPat(
					AnyPat(), AnyPat(), AnyPat(),
					BlockPat(
						ExprInsPat(BindItemPat('xor', AsgxorPat(AnyPat(), AnyPat())))
					)
				)
		)

class Flareon7ChalScheme(Scheme):
	def on_matched_item(self, item, ctx: ASTContext):
		print('%#x' % item.ea)
		try:

			p32 = lambda x: struct.pack("<I", x)
			ns =[]
			ns.append(ctx.get_expr('num0').n._value)
			ns.append(ctx.get_expr('num1').n._value)
			ns.append(ctx.get_expr('num2').n._value)
			ns.append(ctx.get_expr('num3').n._value)
			# ns.append(ctx.get_expr('num4').n._value)
			# ns.append(ctx.get_expr('num5').n._value)
			# ns.append(ctx.get_expr('num6').n._value)
			# ns.append(ctx.get_expr('num7').n._value)
			xor = ctx.get_expr('xor').y.n._value
			# gobj = ctx.get_expr('gobj').obj_ea

			print(b''.join([p32(i ^ xor) for i in ns]))
			# print('%#x' % gobj)
		except:
			pass

		return False


register_storage_scheme("flareon7chal", Flareon7ChalScheme(pattern))