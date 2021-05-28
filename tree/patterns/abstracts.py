import idaapi

class AbstractPattern:
    def __init__(self):
        pass
    
    def __assert(self, cond, msg=""):
        assert cond, "%s: %s" % (self.__class__.__name__, msg)

    def check(self, *args, **kwargs):
        raise NotImplementedError("This is an abstract class")

# any:      Done
# seq:      

# any pattern
class AnyPat(AbstractPattern):
    op = None

    def __init__(self, may_be_none=True):
        self.may_be_none = may_be_none

    def check(self, item):
        return item is not None or self.may_be_none



# sequence of instructions
class SeqPat(AbstractPattern):
    op = None

    def __init__(self, pats, function=None):
        self.seq = pats
        self.length = len(pats)
        self.function = function

    def set_function(self, function):
        self.function = function

    def check(self, instructions):
        parent = self.function.find_parent_of(instructions[0])

        # There is can be no sequence unless its parent is a cblock instruction
        if parent.op != idaapi.cit_cblock:
            return False
    
        for i in range(self.length):
            if not self.seq[i].check(instructions[i]):
                return False
        return True

