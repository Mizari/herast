import idaapi
from .abstracts import AnyPat, AbstractPattern, SeqPat

# [TODO]: consider about merging somehow cit_cdo and cit_cwhile patterns


# block:    
# if:       Done
# while:    Done
# do:       Done
# for:      Done
# switch:   
# return:   Done
# goto:     nope
# asm:      nope



class BlockPat(AbstractPattern):
    op = idaapi.cit_block
    
    def __init__(self, seq=None):
        self._assert(isinstance(seq, SeqPat) or isinstance(seq, AnyPat) or seq is None, \
            "Block pattern must be provided with Sequence pattern")

        self.sequence = seq or AnyPat()

    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        if not isinstance(self.sequence, AnyPat) and len(instruction.cblock) != self.sequence.length:
            return False
        
        return self.sequence.check(instruction)

    @property
    def children(self):
        return (self.sequence, )       


class ExInsPat(AbstractPattern):
    op = idaapi.cit_expr

    def __init__(self, expr=None):
        self.expr = expr or AnyPat()

    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        return self.expr.check(instruction.cexpr)

    @property
    def children(self):
        return (self.expr, )


class IfInsPat(AbstractPattern):
    op = idaapi.cit_if

    def __init__(self, condition=None, then_branch=None, else_branch=None):
        self.condition   = condition   or AnyPat()
        self.then_branch = then_branch or AnyPat()
        self.else_branch = else_branch or AnyPat()

    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        cif = instruction.cif

        return self.condition.check(cif.expr) and \
            self.then_branch.check(cif.ithen) and \
            self.else_branch.check(cif.ielse)

    @property
    def children(self):
        return (self.expr, self.body)


class ForInsPat(AbstractPattern):
    op = idaapi.cit_for

    def __init__(self, init=None, expr=None, step=None, body=None):
        self.init = init or AnyPat()
        self.expr = expr or AnyPat()
        self.step = step or AnyPat()
        self.body = body or AnyPat()


    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        cfor = instruction.cfor

        return self.init.check(cfor.init) and \
            self.expr.check(cfor.expr) and \
            self.step.check(cfor.step) and \
            self.body.check(cfor.body)

    @property
    def children(self):
        return (self.init, self.expr, self.step, self.body)


class RetInsPat(AbstractPattern):
    op = idaapi.cit_return

    def __init__(self, expr=None):
        self.expr = expr or AnyPat()

    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        creturn = instruction.creturn

        return self.expr.check(creturn.expr)

    @property
    def children(self):
        return (self.expr, )


class WhileInsPat(AbstractPattern):
    op = idaapi.cit_while

    def __init__(self, expr=None, body=None):
        self.expr = expr or AnyPat()
        self.body = body or AnyPat()

    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        cwhile = instruction.cwhile

        return self.expr.check(cwhile.expr) and \
            self.body.check(cwhile.body)

    @property
    def children(self):
        return (self.expr, self.body)


class DoInsPat(AbstractPattern):
    op = idaapi.cit_do

    def __init__(self, expr=None, body=None):
        self.expr = expr or AnyPat()
        self.body = body or AnyPat()

    @AbstractPattern.initial_check
    def check(self, instruction) -> bool:
        cdo = instruction.cdo

        return self.body.check(cdo.body) and \
            self.expr.check(cdo.expr) 

    @property
    def children(self):
        return (self.expr, self.body)