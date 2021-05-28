import idaapi

class Matcher:
    def __init__(self, processed_function):
        self.function = processed_function
        self.patterns = list()

    def check_patterns(self, insn):
        for p, h in self.patterns:
            if p.check(insn) is True:
                # if h is not None:
                #     h(insn)
                print("[FOUND]: %#x %d" % (insn.ea, insn.op))

    def insert_pattern(self, pat, handler=None):
        self.patterns.append((pat, handler))