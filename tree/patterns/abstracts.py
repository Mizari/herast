from tree.patterns.expressions import AbstractUnaryOpPattern
import idaapi

# [TODO]: for some reason i've thought that not-recursive check of children may be useful, but forget how can i use it
# [TODO]: so should think about it and also think about splitting AbstractPattern to BasePattern(for "real" patterns with `op` == cot_*|cit_*)
# [TODO]: and BaseAbstractPattern(for abstract patterns, which doesn't have any `op` and performs checking in other way)

# [TODO]: add stripping of cot_cast's before passing node to actual pattern-object, we can call super(self).__init__ with some kwargs
# [TODO]: like skip_casts=False|True and add skipping in __perform_inital_check
class AbstractPattern:
    op = None

    def __init__(self):
        pass
    
    def __assert(self, cond, msg=""):
        assert cond, "%s: %s" % (self.__class__.__name__, msg)

    def check(self, *args, **kwargs):
        raise NotImplementedError("This is an abstract class")

    @staticmethod
    def initial_check(func):
        def __perform_initial_check(self, item, *args, **kwargs):
            if item is None or (item.op != self.op and self.op is not None):
                return False
            else:
                return func(self, item, *args, **kwargs)
        return __perform_initial_check

    @property
    def children(self):
        raise NotImplementedError("An abstract class doesn't have any children")

# any:      Done
# seq:      

# any pattern
class AnyPat(AbstractPattern):
    op = -1

    def __init__(self, may_be_none=True):
        self.may_be_none = may_be_none

    def check(self, item):
        return item is not None or self.may_be_none

    @property
    def children(self):
        return ()



# sequence of instructions
class SeqPat(AbstractPattern):
    op = -1

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
        return tuple(self.pats)

class OrPat(AbstractPattern):
    op = -1

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
        return self.pats
