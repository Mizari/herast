import idaapi

idaapi.require('tree.context')
idaapi.require('tree.patterns.abstracts')

from tree.context import Context
from tree.patterns.abstracts import SeqPat

# [TODO]: mb somehow it should have architecture when patterns can provide some more feedback to matcher, not only True/False
# it can be useful to not traverse every expresion for every pattern-chain, and do it only with a particular-ones
 
class Matcher:
    def __init__(self, processed_function):
        self.function = processed_function
        self.patterns = list()
        self.cache = list()

    def check_patterns(self, item):
        for p, h, c in self.patterns:
            if p.check(item) is True:
                if h is not None:
                    try:
                        h(item, c)
                    except Exception as e:
                        print('[!] Got an exception: %s' % e)
                # print("[FOUND]: %#x %d" % (item.ea, item.op))

    def insert_pattern(self, pat, handler=None):
        ctx = Context()
        ctx.update({'current_function': self.function})
        self.patterns.append((pat, handler, ctx))

    def prepare_cache(self):
        def traverse_pattern(pattern):
            children = pattern.children
            for c in children:
                if isinstance(c, SeqPat):
                    if c not in self.cache:
                        self.cache.append(c)
                traverse_pattern(c)
        
        for pattern in self.patterns:
            traverse_pattern(pattern)

    def has_deep_expressions(self):
        for p, _, _ in self.patterns:
            if p.op >= 0 and p.op < idaapi.cit_empty:
                return True

        return False