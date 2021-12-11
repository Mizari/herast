import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, AsgExprPat, ObjPat, AsgExprPat, AsgxorExprPat
from tree.patterns.instructions import ExInsPat, IfInsPat, BlockPat, ForInsPat

from tree.utils import *

pattern = SeqPat([
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
						SeqPat([
							ExInsPat(BindExpr('xor', AsgxorExprPat(AnyPat(), AnyPat())))
						])
					)
				)
		])

import struct
def handler(item, ctx):
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
	(pattern, handler)
]