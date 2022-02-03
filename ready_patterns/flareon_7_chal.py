import struct

from tree.patterns.abstracts import *
from tree.patterns.expressions import AsgExprPat, AsgxorExprPat
from tree.patterns.instructions import ExInsPat, BlockPat, ForInsPat

from schemes.single_pattern_schemes import SPScheme

pattern = SeqPat(
				# ExInsPat(AsgExprPat(BindExpr('gobj', ObjPat()), SkipCasts(CallExprPat(ObjPat(name='j__malloc_base'), ignore_arguments=True)))),
				# ExInsPat(AnyPat()),
				ExInsPat(AsgExprPat(AnyPat(), BindExpr('num0', AnyPat()))),
				ExInsPat(AsgExprPat(AnyPat(), BindExpr('num1', AnyPat()))),
				ExInsPat(AsgExprPat(AnyPat(), BindExpr('num2', AnyPat()))),
				ExInsPat(AsgExprPat(AnyPat(), BindExpr('num3', AnyPat()))),
				# ExInsPat(AsgExprPat(AnyPat(), BindExpr('num4', AnyPat()))),
				# ExInsPat(AsgExprPat(AnyPat(), BindExpr('num5', AnyPat()))),
				# ExInsPat(AsgExprPat(AnyPat(), BindExpr('num6', AnyPat()))),
				# ExInsPat(AsgExprPat(AnyPat(), BindExpr('num7', AnyPat()))),
				ForInsPat(
					AnyPat(), AnyPat(), AnyPat(),
					BlockPat(
						ExInsPat(BindExpr('xor', AsgxorExprPat(AnyPat(), AnyPat())))
					)
				)
		)

class Flareon7ChalScheme(SPScheme):
	def on_matched_item(self, item, ctx: PatternContext):
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


__exported = [
	Flareon7ChalScheme("flareon7chal", pattern)
]