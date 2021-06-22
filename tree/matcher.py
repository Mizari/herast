import idaapi

# [TODO]: mb somehow it should have architecture when patterns can provide some more feedback to matcher, not only True/False
# it can be useful to not traverse every expresion for every pattern-chain, and do it only with a particular-ones
 
class Matcher:
    def __init__(self, processed_function):
        self.function = processed_function
        self.patterns = list()
        self.deep_patterns = list()

    def check_patterns(self, item):
        for p, h in self.patterns:
            if p.check(item) is True:
                if h is not None:
                    try:
                        h(item)
                    except Exception as e:
                        print('[!] Got an exception: %s' % e)
                # print("[FOUND]: %#x %d" % (item.ea, item.op))

    def insert_pattern(self, pat, handler=None):
        self.patterns.append((pat, handler))


    # [TODO]: make traversal of patterns to check if there is at least one deep expression pattern
    def has_deep_expressions(self):
        return True