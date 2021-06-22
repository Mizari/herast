import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.consts')

from tree.patterns.abstracts import AnyPat, AbstractPattern, SeqPat
from tree.consts import binary_expressions_ops, unary_expressions_ops, op2str


class CallExprPat(AbstractPattern):
    op = idaapi.cot_call

    def __init__(self, calling_function, arguments, skip_missing_args=True):
        self.calling_function = calling_function
        self.arguments = arguments

    @AbstractPattern.initial_check
    def check(self, expression) -> bool:
        return True

    @property
    def children(self):
        return (self.calling_function, *self.arguments)

class AbstractUnaryOpPattern(AbstractPattern):
    op = None

    def __init__(self, operand):
        self.operand = operand

    @AbstractPattern.initial_check
    def check(self, expression) -> bool:
        return self.operand.check(expression.x)

    @property
    def children(self):
        return (self.operand, )


class AbstractBinaryOpPattern(AbstractPattern):
    op = None

    def __init__(self, first_operand, second_operand, symmetric=True):
        self.first_operand = first_operand
        self.second_operand = second_operand
        self.symmetric = symmetric

    @AbstractPattern.initial_check
    def check(self, expression) -> bool:
        first_op_second = self.first_operand.check(expression.x) and self.second_operand.check(expression.y)
        if self.symmetric:
            second_op_first = self.first_operand.check(expression.y) and self.second_operand.check(expression.x)
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

