import idaapi


class Context(object):
    def __init__(self):
        self.data = dict()
    
    def clear(self):
        self.data.clear()

    def update(self, values):
        assert type(values) is dict
        self.data.update(values)