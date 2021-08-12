import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.consts')
idaapi.require('tree.utils')

from tree.patterns.abstracts import AnyPat, AbstractPattern, SeqPat
from tree.consts import binary_expressions_ops, unary_expressions_ops, op2str
from tree.utils import resolve_name_address


# [TODO]: Add check of arguments, atm it's just not checked at all
class CallExprPat(AbstractPattern):
    op = idaapi.cot_call

    def __init__(self, calling_function, *arguments, skip_missing_args=True):
        self.calling_function = calling_function
        self.arguments = arguments
        self.skip_missing_args = skip_missing_args

    @AbstractPattern.initial_check
    def check(self, expression, ctx) -> bool:
        return self.calling_function.check(expression.x, ctx)

    @property
    def children(self):
        return (self.calling_function, *self.arguments)


class HelperExprPat(AbstractPattern):
    op = idaapi.cot_helper

    def __init__(self, helper_name=None):
        self.helper_name = helper_name
    
    @AbstractPattern.initial_check
    def check(self, expression, ctx) -> bool:
        return self.helper_name == expression.helper if self.helper_name is not None else True

    @property
    def children(self):
        return ()

class ObjPat(AbstractPattern):
    op = idaapi.cot_obj

    def __init__(self, name=None, ea=None):
        self.ea = ea
        if ea is None and name is not None:
            self.ea = resolve_name_address(name)
            self._assert(self.ea != idaapi.BADADDR, "Unable to resolve '%s' address" % (name))

    @AbstractPattern.initial_check
    def check(self, expression, ctx) -> bool:
        if self.ea is None:
            return True
        
        return self.ea == expression.obj_ea 
                

class AbstractUnaryOpPattern(AbstractPattern):
    op = None

    def __init__(self, operand):
        self.operand = operand

    @AbstractPattern.initial_check
    def check(self, expression, ctx) -> bool:
        return self.operand.check(expression.x, ctx)

    @property
    def children(self):
        return (self.operand, )


class AbstractBinaryOpPattern(AbstractPattern):
    op = None

    def __init__(self, first_operand, second_operand, symmetric=False):
        self.first_operand = first_operand
        self.second_operand = second_operand
        self.symmetric = symmetric

    @AbstractPattern.initial_check
    def check(self, expression, ctx) -> bool:
        first_op_second = self.first_operand.check(expression.x, ctx) and self.second_operand.check(expression.y, ctx)
        if self.symmetric:
            second_op_first = self.first_operand.check(expression.y, ctx) and self.second_operand.check(expression.x, ctx)
            return first_op_second or second_op_first
        else:
            return first_op_second

    @property
    def children(self):
        return (self.first_operand, self.second_operand)


import sys
module = sys.modules[__name__]

# [TODO]: name-overwriting check
for op in unary_expressions_ops:
    name = '%sExprPat' % op2str[op].replace('cot_', '').capitalize()
    vars(module)[name] = type(name, (AbstractUnaryOpPattern,), {'op': op})

for op in binary_expressions_ops:
    name = '%sExprPat' % op2str[op].replace('cot_', '').capitalize()
    vars(module)[name] = type(name, (AbstractBinaryOpPattern,), {'op': op})