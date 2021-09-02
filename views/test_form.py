from PyQt5 import QtCore, QtWidgets

import idaapi


class ScriptManager(idaapi.PluginForm):
    def __init__(self, patterns_model):
        super(ScriptManager, self).__init__()
        self.patterns_model = patterns_model
        self.parent = None
    
    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
            # "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('HeRAST Patterns View')

        btn_disable = QtWidgets.QPushButton("&Disable")
        btn_enable = QtWidgets.QPushButton("&Enable")
        btn_reload = QtWidgets.QPushButton("&Reload")
        btn_reload_all = QtWidgets.QPushButton("&Reload All")
        btn_disable_all = QtWidgets.QPushButton("&Disable All")
        # btn_reload_all.setStyleSheet("QPushButton {width: 300px; height: 20px;}")
        


        patterns_list = QtWidgets.QListView()
        patterns_list.setModel(self.patterns_model)
        patterns_list.setMaximumWidth(patterns_list.size().width() / 3)

        # pattern_description = QtWidgets.QListView()
        # pattern_description.setModel(self.patterns_model)

        bottom_btns_grid_box = QtWidgets.QGridLayout()
        bottom_btns_grid_box.addWidget(btn_reload_all, 0, 0)
        bottom_btns_grid_box.addWidget(btn_disable_all, 0, 1)

        top_btns_grid_box = QtWidgets.QGridLayout()
        top_btns_grid_box.addWidget(btn_disable, 0, 0)
        top_btns_grid_box.addWidget(btn_enable, 0, 1)
        top_btns_grid_box.addWidget(btn_reload, 0, 2)

        pattern_text_area = QtWidgets.QTextEdit()
        pattern_text_area.setReadOnly(True)
        # text_area.setFontPointSize(10)
        pattern_text_area.setText('''import idaapi

idaapi.require('tree.context')
idaapi.require('tree.patterns.abstracts')

from tree.context import Context
from tree.patterns.abstracts import SeqPat, BindExpr

# [TODO]: mb somehow it should have architecture when patterns can provide some more feedback to matcher, not only True/False testtesttesttesttest testtest test test test test test test 
# it can be useful to not traverse every expresion for every pattern-chain, and do it only with a particular-ones
 
class Matcher:
    def __init__(self, processed_function):
        self.function = processed_function
        self.patterns = list()

    def check_patterns(self, item):
        for p, h, c in self.patterns:
            try:
                if p.check(item, c):
                    if h is not None:
                        return h(item, c)
                        
            except Exception as e:
                print('[!] Got an exception: %s' % e)
                raise e
        
        return False

    def insert_pattern(self, pat, handler=None):
        ctx = dict()
        ctx.update({"current_function": self.function})
        self.patterns.append((pat, handler, ctx))

    def expressions_traversal_is_needed(self):
        for p, _, _ in self.patterns:
            if p.op >= 0 and p.op < idaapi.cit_empty or isinstance(p, BindExpr):
                return True

        return False''')

        loading_log_area = QtWidgets.QTextEdit()
        loading_log_area.setReadOnly(True)
        loading_log_area.setText("""IDAPython: Error while calling Python callback <OnCreate>:
Traceback (most recent call last):
  File "D:/Share/git-stuff/herast/views/test_form.py", line 14, in OnCreate
    self.init_ui()
  File "D:/Share/git-stuff/herast/views/test_form.py", line 54, in init_ui
    with open('./test_form.py', 'r') as f:
FileNotFoundError: [Errno 2] No such file or directory: './test_form.py'""")

        # [TODO]: do something with fucking height goddamnit, unless just limit maximum height of 150 (?) or something
        loading_log_area.setStyleSheet("height: 50")

        vertical_box = QtWidgets.QVBoxLayout()
        vertical_box.setSpacing(0)

        # inner_vertical_box = QtWidgets.QVBoxLayout()
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(pattern_text_area)
        splitter.addWidget(loading_log_area)

        # vertical_box.addWidget(pattern_text_area)
        # vertical_box.addWidget(loading_log_area)
        vertical_box.addWidget(splitter)
        vertical_box.addLayout(top_btns_grid_box)
        vertical_box.addLayout(bottom_btns_grid_box)

        horizontal_box = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
        horizontal_box.addWidget(patterns_list)
        horizontal_box.addLayout(vertical_box)
        # horizontal_box.addWidget(pattern_description)
        

        self.parent.setLayout(horizontal_box)

    def OnClose(self, form):
        pass

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)


class ShowScriptManager(idaapi.action_handler_t):
    description = "Show manager of herast's script's"
    hotkey = 'Shift+M'


    def __init__(self):
        super(ShowScriptManager, self).__init__()

    def update(self, ctx):
        return True

    def activate(self, ctx):
        tform = idaapi.find_widget("Script Manager")
        if tform:
            tform.activate_widget(tform, true)
        else:
            ScriptManager(LoadedPatternsModel()).Show()

    @property
    def name(self):
        return 'herast:' + type(self).__name__    


class LoadedPatternsModel(QtCore.QAbstractListModel ):
    def __init__(self, *args):
        super(LoadedPatternsModel, self).__init__(*args)
        self.items = ['test1', 'test2', 'test3']
    
    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.items)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return QtCore.QVariant()

        if index.row() >= len(self.items):
            return QtCore.QVariant()

        if role == QtCore.Qt.DisplayRole:
            return QtCore.QVariant(self.items[index.row()])
        else:
            return QtCore.QVariant()

    # def setData(self, index, value, role):
    #     return True

action = ShowScriptManager()
idaapi.register_action(idaapi.action_desc_t(action.name, action.description, action, action.hotkey))    

# action = LoadedPatternsModel()
# ShowScriptManager().activate(None)