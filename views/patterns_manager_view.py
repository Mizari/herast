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

		btn_reload = QtWidgets.QPushButton("&Reload")
		btn_enable = QtWidgets.QPushButton("&Enable")
		btn_disable = QtWidgets.QPushButton("&Disable")
		btn_refresh_all = QtWidgets.QPushButton("Refresh all")
		btn_disable_all = QtWidgets.QPushButton("Disable All")

		btn_disable.setShortcut('d')
		btn_enable.setShortcut('e')
		btn_reload.setShortcut('r')
		# btn_refresh.setShortcut('???')
		# btn_disable_all.setShortcut('???')


		patterns_list = QtWidgets.QListView()
		patterns_list.setModel(self.patterns_storage_model)
		patterns_list.setMaximumWidth(patterns_list.size().width() // 3)
		patterns_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

		bottom_btns_grid_box = QtWidgets.QGridLayout()
		bottom_btns_grid_box.addWidget(btn_refresh_all, 0, 0)
		bottom_btns_grid_box.addWidget(btn_disable_all, 0, 1)

		top_btns_grid_box = QtWidgets.QGridLayout()
		top_btns_grid_box.addWidget(btn_disable, 0, 0)
		top_btns_grid_box.addWidget(btn_enable, 0, 1)
		top_btns_grid_box.addWidget(btn_reload, 0, 2)

		pattern_text_area = PatternSourceView(patterns_list.model())
		pattern_text_area.setReadOnly(True)
		
		loading_log_area = PatternLogView(patterns_list.model())
		loading_log_area.setReadOnly(True)
		loading_log_area.setMaximumHeight(100)

		splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
		splitter.addWidget(pattern_text_area)
		splitter.addWidget(loading_log_area)


		patterns_list.selectionModel().currentChanged.connect(lambda cur, prev: pattern_text_area.switch_source_data(cur, prev))
		patterns_list.selectionModel().currentChanged.connect(lambda cur, prev: loading_log_area.switch_log_data(cur, prev))
		patterns_list.setCurrentIndex(patterns_list.model().index(0))

		patterns_list.model().dataChanged.connect(lambda start, end: pattern_text_area.reload_source_data(start, end, patterns_list.selectedIndexes()))
		patterns_list.model().dataChanged.connect(lambda start, end: loading_log_area.reload_log_data(start, end, patterns_list.selectedIndexes()))

		vertical_box = QtWidgets.QVBoxLayout()
		vertical_box.setSpacing(0)
		vertical_box.addWidget(splitter)
		vertical_box.addLayout(top_btns_grid_box)
		vertical_box.addLayout(bottom_btns_grid_box)

		horizontal_box = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		horizontal_box.addWidget(patterns_list)
		horizontal_box.addLayout(vertical_box)

		btn_disable.clicked.connect(lambda: patterns_list.model().disable_pattern(patterns_list.selectedIndexes()))
		btn_enable.clicked.connect(lambda: patterns_list.model().enable_pattern(patterns_list.selectedIndexes()))
		btn_reload.clicked.connect(lambda: patterns_list.model().reload_pattern(patterns_list.selectedIndexes()))
		btn_disable_all.clicked.connect(lambda: patterns_list.model().disable_all_patterns())

		btn_refresh_all.clicked.connect(lambda: patterns_list.model().refresh_patterns())

		self.parent.setLayout(horizontal_box)

	def OnClose(self, form):
		pass

	def Show(self, caption=None, options=0):
		return idaapi.PluginForm.Show(self, caption, options=options)

class PatternSourceView(QtWidgets.QTextEdit):
	def __init__(self, storage, *args, **kwargs):
		self.storage = storage
		super(PatternSourceView, self).__init__(*args, **kwargs)

	def switch_source_data(self, current, previous):
		if current.row() < len(self.storage.ready_patterns):
			self.setPlainText(self.storage.ready_patterns[current.row()].source)
		else:
			self.setPlaintText('')

	def reload_source_data(self, changed_start, changed_end, selected):
		inside = lambda _start, _end, _val: _start <= _val <= _end

		if changed_start.row() < len(self.storage.ready_patterns) and changed_end.row() < len(self.storage.ready_patterns) \
				and changed_end.row() >= changed_start.row() and inside(changed_start.row(), changed_end.row(), selected[0].row()):
			self.setPlainText(self.storage.ready_patterns[selected[0].row()].source)
		
			

class PatternLogView(QtWidgets.QTextEdit):
	def __init__(self, storage, *args, **kwargs):
		self.storage = storage
		super(PatternLogView, self).__init__(*args, **kwargs)

	def switch_log_data(self, current, previous):
		if current.row() < len(self.storage.ready_patterns):
			self.setPlainText(self.storage.ready_patterns[current.row()].log)
		else:
			self.setPlaintText('')

	def reload_log_data(self, changed_start, changed_end, selected):
		inside = lambda _start, _end, _val: _start <= _val <= _end

		if changed_start.row() < len(self.storage.ready_patterns) and changed_end.row() < len(self.storage.ready_patterns) \
				and changed_end.row() >= changed_start.row() and inside(changed_start.row(), changed_end.row(), selected[0].row()):
			self.setPlainText(self.storage.ready_patterns[selected[0].row()].log)


class ShowScriptManager(idaapi.action_handler_t):
	description = "Show manager of herast's script's"
	hotkey = 'Shift+M'

	def __init__(self, model):
		super(ShowScriptManager, self).__init__()
		self.model = model

	def update(self, ctx):
		return True

	def activate(self, ctx):
		tform = idaapi.find_widget("Script Manager")
		if tform:
			tform.activate_widget(tform, True)
		else:
			ScriptManager(self.model).Show()

	@property
	def name(self):
		return 'herast:' + type(self).__name__    


# m = PatternStorageModel()
# action = ShowScriptManager(m)
# idaapi.register_action(idaapi.action_desc_t(action.name, action.description, action, action.hotkey))    
