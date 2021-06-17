import idaapi
from .abstracts import AnyPat, AbstractPattern, SeqPat



class CallExprPat(AbstractPattern):
    op = idaapi.cot_call

    def __init__(self, calling_function, arguments):
        pass



class AbstractUnaryOpPattern(AbstractPattern):
    op = None

    def __init__(self, operand):
        self.operand = operand

    def check(self, expression):
        if expression is None or expression.op != self.op:
            return False
        
        return self.operand.check(expression.x)


class AbstractBinaryOpPattern(AbstractPattern):
    op = None

    def __init__(self, first_operand, second_operand, symmetric=True):
        self.first_operand = first_operand
        self.second_operand = second_operand
        self.symmetric = symmetric

    def check(self, expression):
        if expression is None or expression.op != self.op:
            return False

        first_op_second = self.first_operand.check(expression.x) and self.second_operand.check(expression.y)
        if self.symmetric:
            second_op_first = self.first_operand.check(expression.y) and self.second_operand.check(expression.x)
            return first_op_second or second_op_first
        else:
            return first_op_second


import sys
module = sys.modules[__name__]

unary_operations = []
binary_operations = []
