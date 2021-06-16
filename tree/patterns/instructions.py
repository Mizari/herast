import idaapi
from .abstracts import AnyPat, AbstractPattern, SeqPat

# TODO: consider about merging somehow cit_cdo and cit_cwhile patterns


# block:    
# if:       Done
# while:    Done
# do:       Done
# for:      Done
# switch:   
# return:   Done
# goto:     nope
# asm:      nope



# idaapi.cit_block
class BlockPat(AbstractPattern):
    def __init__(self, seq=None):
        self.__assert(isinstance(seq, SeqPat) or isinstance(seq, AnyPat) or seq is None, \
            "Block pattern must be provided with Sequence pattern")

        self.op = idaapi.cit_block
        self.sequence = seq or AnyPat()

    def check(self, instruction):
        if instruction is None or self.op != instruction.op:
            return False

        return self.sequence.check(instruction)


# idaapi.cit_expr
class ExInsPat(AbstractPattern):
    def __init__(self, expr=None):
        self.op = idaapi.cit_expr
        self.expr = expr or AnyPat()

    def check(self, instruction):
        if instruction is None or instruction.op != self.op:
            return False
        
        return self.expr.check(instruction.cexpr)

    @property
    def children(self):
        return (self.expr, )


# idaapi.cit_cif
class IfInsPat(AbstractPattern):
    def __init__(self, condition=None, then_branch=None, else_branch=None):
        self.op = idaapi.cit_if
        self.condition   = condition   or AnyPat()
        self.then_branch = then_branch or AnyPat()
        self.else_branch = else_branch or AnyPat()

    def check(self, instruction):
        if instruction is None or instruction.op != self.op:
            return False

        cif = instruction.cif

        return self.condition.check(cif.expr) and \
            self.then_branch.check(cif.ithen) and \
            self.else_branch.check(cif.ielse)

    @property
    def children(self):
        return (self.expr, self.body)


# idaapi.cit_for
class ForInsPat(AbstractPattern):
    def __init__(self, init=None, expr=None, step=None, body=None):
        self.op = idaapi.cit_for
        self.init = init or AnyPat()
        self.expr = expr or AnyPat()
        self.step = step or AnyPat()
        self.body = body or AnyPat()


    def check(self, instruction):
        if instruction is None or instruction.op != self.op:
            return False

        cfor = instruction.cfor

        return self.init.check(cfor.init) and \
            self.expr.check(cfor.expr) and \
            self.step.check(cfor.step) and \
            self.body.check(cfor.body)

    @property
    def children(self):
        return (self.init, self.expr, self.step, self.body)


# idaapi.cit_return
class RetInsPat(AbstractPattern):
    def __init__(self, expr=None):
        self.op = idaapi.cit_return
        self.expr = expr or AnyPat()

    def check(self, instruction):
        if instruction is None or self.op != instruction.op:
            return False

        creturn = instruction.creturn

        return self.expr.check(creturn.expr)

    @property
    def children(self):
        return (self.expr, )


# idaapi.cit_while
class WhileInsPat(AbstractPattern):
    def __init__(self, expr=None, body=None):
        self.op = idaapi.cit_while
        self.expr = expr or AnyPat()
        self.body = body or AnyPat()

    def check(self, instruction):
        if instruction is None or self.op != instruction.op:
            return False

        cwhile = instruction.cwhile

        return self.expr.check(cwhile.expr) and \
            self.body.check(cwhile.body)

    @property
    def children(self):
        return (self.expr, self.body)


# idaapi.cit_cdo
class DoInsPat(AbstractPattern):
    def __init__(self, expr=None, body=None):
        self.op = idaapi.cit_cdo
        self.expr = expr or AnyPat()
        self.body = body or AnyPat()

    def check(self, instruction):
        if instruction is None or self.op != instruction.op:
            return False

        cdo = instruction.cdo

        return self.body.check(cdo.body) and \
            self.expr.check(cdo.expr) 

    @property
    def children(self):
        return (self.expr, self.body)