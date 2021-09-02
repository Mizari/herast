from PyQt5 import QtCore, QtWidgets, QtGui

import idaapi


class ScriptManager(idaapi.PluginForm):
    def __init__(self, patterns_storage_model):
        super(ScriptManager, self).__init__()
        self.patterns_storage_model = patterns_storage_model
        self.parent = None
    
    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('HeRAST Patterns View')

        btn_disable = QtWidgets.QPushButton("&Disable")
        btn_enable = QtWidgets.QPushButton("&Enable")
        btn_reload = QtWidgets.QPushButton("&Reload")
        btn_reload_all = QtWidgets.QPushButton("Reload All")
        btn_disable_all = QtWidgets.QPushButton("Disable All")

        btn_disable.setShortcut('d')
        btn_enable.setShortcut('e')
        btn_reload.setShortcut('r')
        # btn_reload_all.setShortcut('???')
        # btn_disable_all.setShortcut('???')


        patterns_list = QtWidgets.QListView()
        patterns_list.setModel(self.patterns_storage_model)
        patterns_list.setMaximumWidth(patterns_list.size().width() // 3)

        bottom_btns_grid_box = QtWidgets.QGridLayout()
        bottom_btns_grid_box.addWidget(btn_reload_all, 0, 0)
        bottom_btns_grid_box.addWidget(btn_disable_all, 0, 1)

        top_btns_grid_box = QtWidgets.QGridLayout()
        top_btns_grid_box.addWidget(btn_disable, 0, 0)
        top_btns_grid_box.addWidget(btn_enable, 0, 1)
        top_btns_grid_box.addWidget(btn_reload, 0, 2)

        pattern_text_area = QtWidgets.QTextEdit()
        pattern_text_area.setReadOnly(True)
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
        loading_log_area.setMaximumHeight(100)
        loading_log_area.setText("""IDAPython: Error while calling Python callback <OnCreate>:
Traceback (most recent call last):
  File "D:/Share/git-stuff/herast/views/test_form.py", line 14, in OnCreate
    self.init_ui()
  File "D:/Share/git-stuff/herast/views/test_form.py", line 54, in init_ui
    with open('./test_form.py', 'r') as f:
FileNotFoundError: [Errno 2] No such file or directory: './test_form.py'""")

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(pattern_text_area)
        splitter.addWidget(loading_log_area)

        vertical_box = QtWidgets.QVBoxLayout()
        vertical_box.setSpacing(0)
        vertical_box.addWidget(splitter)
        vertical_box.addLayout(top_btns_grid_box)
        vertical_box.addLayout(bottom_btns_grid_box)

        horizontal_box = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
        horizontal_box.addWidget(patterns_list)
        horizontal_box.addLayout(vertical_box)

        
        # [TODO]: after compliting part in module, don't forget to uncomment this lines
        # btn_disable.clicked.connect(lambda: self.patterns_storage_model.disable_pattern(patterns_list.selectedIndexes()))
        # btn_enable.clicked.connect(lambda: self.patterns_storage_model.enable_pattern(patterns_list.selectedIndexes()))
        # btn_reload.clicked.connect(lambda: self.patterns_storage_model.reload_pattern(patterns_list.selectedIndexes()))
        # btn_disable_all.clicked.connect(lambda: self.patterns_storage_model.disable_all_patterns())
        # btn_reload_all.clicked.connect(lambda: self.patterns_storage_model.reload_all_patterns())

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
            tform.activate_widget(tform, True)
        else:
            ScriptManager(PatternStorageModel()).Show()

    @property
    def name(self):
        return 'herast:' + type(self).__name__    


class PatternStorageModel(QtCore.QAbstractListModel):
    def __init__(self, *args):
        super(PatternStorageModel, self).__init__(*args)
        self.ready_patterns = ['call_explore.py', 'collapse_exception_branch.bin', 'objc_patterns.txt', 'huuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuge_test.py']
    
    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.ready_patterns)

    def data(self, index, role):
        if not index.isValid():
            return QtCore.QVariant()

        if index.row() >= len(self.ready_patterns):
            return QtCore.QVariant()

        item = self.ready_patterns[index.row()]

        if role == QtCore.Qt.DisplayRole:
            return QtCore.QVariant(item)

        elif role == QtCore.Qt.BackgroundRole:
            if item.endswith('py'):
                return _color_with_opacity(QtCore.Qt.green)
            elif item.endswith('txt'):
                return _color_with_opacity(QtCore.Qt.red)
            elif item.endswith('bin'):
                return _color_with_opacity(QtCore.Qt.gray)
        else:
            return QtCore.QVariant()

    def disable_pattern(self, indices):
        pass

    def enable_pattern(self, indices):
        pass
        # for qindex in indices:
            # self.ready_patterns[qindex.row()].

    def reload_pattern(self, indices):
        for qindex in indices:
            self.ready_patterns[qindex.row()].reload()

    def reload_all_patterns(self):
        pass

    def disable_all_patterns(self):
        pass


def _color_with_opacity(tone, opacity=160):
    color = QtGui.QColor(tone)
    color.setAlpha(opacity)
    return color
            

action = ShowScriptManager()
idaapi.register_action(idaapi.action_desc_t(action.name, action.description, action, action.hotkey))    