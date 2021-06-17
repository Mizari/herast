import idaapi

class AbstractPattern:
    def __init__(self):
        pass
    
    def __assert(self, cond, msg=""):
        assert cond, "%s: %s" % (self.__class__.__name__, msg)

    def check(self, *args, **kwargs):
        raise NotImplementedError("This is an abstract class")

    @property
    def children(self):
        raise NotImplementedError("An abstract class doesn't have any children")

# any:      Done
# seq:      

# any pattern
class AnyPat(AbstractPattern):
    op = None

    def __init__(self, may_be_none=True):
        self.may_be_none = may_be_none

    def check(self, item):
        return item is not None or self.may_be_none

    @property
    def children(self):
        return ()



# sequence of instructions
class SeqPat(AbstractPattern):
    op = None

    def __init__(self, pats, function=None):
        if type(pats) is not tuple and type(pats) is not list:
            pats = (pats, )

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

    @property
    def children(self):
        return pats

class OrPat(AbstractPattern):
    op = None

    # [NOTE]: thought about lazy checking feature, but decided that it kinda useless atm
    def __init__(self, pats):
        self.__assert(len(pats) > 1, "Passing one or less patterns to OrPat is useless")
        self.pats = tuple(pats)
    
    def check(self, item):
        for p in self.pats:
            if p.check(item):
                return True
        
        return False

    @property
    def children(self):
        return pats
