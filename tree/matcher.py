import idaapi

idaapi.require('tree.context')

from tree.context import Context

# [TODO]: mb somehow it should have architecture when patterns can provide some more feedback to matcher, not only True/False
# it can be useful to not traverse every expresion for every pattern-chain, and do it only with a particular-ones
 
class Matcher:
    def __init__(self, processed_function):
        self.function = processed_function
        self.patterns = list()

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


    def has_deep_expressions(self):
        for p, _, _ in self.patterns:
            if p.op >= 0 and p.op < idaapi.cit_empty:
                return True

        return False