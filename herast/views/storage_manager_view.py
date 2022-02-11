from PyQt5 import QtCore, QtWidgets, QtGui

import idaapi

from herast.storage_manager import StorageManager


"""
class StorageManagerForm(idaapi.PluginForm):
	def __init__(self, storage_manager_model: StorageManager):
		super(StorageManagerForm, self).__init__()
		self.storage_manager_model = storage_manager_model
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
		self.parent.setWindowTitle('HeRAST Scheme Storages View')

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


		storages_list = QtWidgets.QListView()
		storages_list.setModel(self.storage_manager_model)
		storages_list.setMaximumWidth(storages_list.size().width() // 3)
		storages_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

		bottom_btns_grid_box = QtWidgets.QGridLayout()
		bottom_btns_grid_box.addWidget(btn_refresh_all, 0, 0)
		bottom_btns_grid_box.addWidget(btn_disable_all, 0, 1)

		top_btns_grid_box = QtWidgets.QGridLayout()
		top_btns_grid_box.addWidget(btn_disable, 0, 0)
		top_btns_grid_box.addWidget(btn_enable, 0, 1)
		top_btns_grid_box.addWidget(btn_reload, 0, 2)

		storage_text_area = StorageSourceView(storages_list.model())
		storage_text_area.setReadOnly(True)

		loading_log_area = StorageLogView(storages_list.model())
		loading_log_area.setReadOnly(True)
		loading_log_area.setMaximumHeight(100)

		splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
		splitter.addWidget(storage_text_area)
		splitter.addWidget(loading_log_area)


		storages_list.selectionModel().currentChanged.connect(lambda cur, prev: storage_text_area.switch_source_data(cur, prev))
		storages_list.selectionModel().currentChanged.connect(lambda cur, prev: loading_log_area.switch_log_data(cur, prev))
		storages_list.setCurrentIndex(storages_list.model().index(0))

		storages_list.model().dataChanged.connect(lambda start, end: storage_text_area.reload_source_data(start, end, storages_list.selectedIndexes()))
		storages_list.model().dataChanged.connect(lambda start, end: loading_log_area.reload_log_data(start, end, storages_list.selectedIndexes()))

		vertical_box = QtWidgets.QVBoxLayout()
		vertical_box.setSpacing(0)
		vertical_box.addWidget(splitter)
		vertical_box.addLayout(top_btns_grid_box)
		vertical_box.addLayout(bottom_btns_grid_box)

		horizontal_box = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		horizontal_box.addWidget(storages_list)
		horizontal_box.addLayout(vertical_box)

		btn_disable.clicked.connect(lambda: storages_list.model().disable_storage(storages_list.selectedIndexes()))
		btn_enable.clicked.connect(lambda: storages_list.model().enable_storage(storages_list.selectedIndexes()))
		btn_reload.clicked.connect(lambda: storages_list.model().reload_storage(storages_list.selectedIndexes()))
		btn_disable_all.clicked.connect(lambda: storages_list.model().disable_all_storages())

		btn_refresh_all.clicked.connect(lambda: storages_list.model().refresh_storages())

		self.parent.setLayout(horizontal_box)

	def OnClose(self, form):
		pass

	def Show(self, caption=None, options=0):
		return idaapi.PluginForm.Show(self, caption, options=options)

class StorageSourceView(QtWidgets.QTextEdit):
	def __init__(self, storage: StorageManager, *args, **kwargs):
		self.storage = storage
		super(StorageSourceView, self).__init__(*args, **kwargs)
		self.setTabStopDistance(QtGui.QFontMetricsF(self.font()).width(' ') * 4)

	def switch_source_data(self, current, previous):
		if current.row() < len(self.storage.schemes_storages):
			self.setPlainText(self.storage.schemes_storages[current.row()].source)
		else:
			self.setPlaintText('')

	def reload_source_data(self, changed_start, changed_end, selected):
		inside = lambda _start, _end, _val: _start <= _val <= _end

		if changed_start.row() < len(self.storage.schemes_storages) and changed_end.row() < len(self.storage.schemes_storages) \
				and changed_end.row() >= changed_start.row() and inside(changed_start.row(), changed_end.row(), selected[0].row()):
			self.setPlainText(self.storage.schemes_storages[selected[0].row()].source)



class StorageLogView(QtWidgets.QTextEdit):
	def __init__(self, storage: StorageManager, *args, **kwargs):
		self.storage = storage
		super(StorageLogView, self).__init__(*args, **kwargs)

	def switch_log_data(self, current, previous):
		if current.row() < len(self.storage.schemes_storages):
			self.setPlainText(self.storage.schemes_storages[current.row()].log)
		else:
			self.setPlaintText('')

	def reload_log_data(self, changed_start, changed_end, selected):
		inside = lambda _start, _end, _val: _start <= _val <= _end

		if changed_start.row() < len(self.storage.schemes_storages) and changed_end.row() < len(self.storage.schemes_storages) \
				and changed_end.row() >= changed_start.row() and inside(changed_start.row(), changed_end.row(), selected[0].row()):
			self.setPlainText(self.storage.schemes_storages[selected[0].row()].log)
"""

class BoldDelegate(QtWidgets.QStyledItemDelegate):
	def paint(self, painter, option, index):
		if not index.isValid():
			return 

		if index.internalPointer().is_directory():
			option.font.setWeight(QtGui.QFont.Bold)
		QtWidgets.QStyledItemDelegate.paint(self, painter, option, index)


class StorageManagerForm(idaapi.PluginForm):
	def __init__(self):
		super(StorageManagerForm, self).__init__()


	def OnCreate(self, form):
		self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
		self.init_ui()

	def init_ui(self):
		self.parent.resize(400, 600)
		self.parent.setWindowTitle('HUYPIZDA')

		self.model = StorageManager()
		# self.model = QtGui.QStandardItemModel()
		# self.model.setHorizontalHeaderLabels(["Name"])
		
		patterns_list = QtWidgets.QTreeView()
		patterns_list.setModel(self.model)
		patterns_list.setItemDelegate(BoldDelegate())
		# self.tree_view.setSortingEnabled(True)


		btn_reload = QtWidgets.QPushButton("&Reload")
		btn_enable = QtWidgets.QPushButton("&Enable")
		btn_disable = QtWidgets.QPushButton("&Disable")
		btn_refresh_all = QtWidgets.QPushButton("Refresh all")
		btn_disable_all = QtWidgets.QPushButton("Disable All")

		btn_expand_all = QtWidgets.QPushButton("Expand all")
		btn_collapse_all = QtWidgets.QPushButton("Collapse all")

		btn_expand_all.clicked.connect(patterns_list.expandAll)
		btn_collapse_all.clicked.connect(patterns_list.collapseAll)

		patterns_list.setMaximumWidth(patterns_list.size().width() // 3)
		patterns_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

		patterns_list.horizontalScrollBar().setEnabled(True)

		bottom_btns_grid_box = QtWidgets.QGridLayout()
		bottom_btns_grid_box.addWidget(btn_refresh_all, 0, 0)
		bottom_btns_grid_box.addWidget(btn_disable_all, 0, 1)

		top_btns_grid_box = QtWidgets.QGridLayout()
		top_btns_grid_box.addWidget(btn_disable, 0, 0)
		top_btns_grid_box.addWidget(btn_enable, 0, 1)
		top_btns_grid_box.addWidget(btn_reload, 0, 2)

		pattern_text_area = QtWidgets.QTextEdit()
		pattern_text_area.setReadOnly(True)
		
		loading_log_area = QtWidgets.QTextEdit()
		loading_log_area.setReadOnly(True)
		loading_log_area.setMaximumHeight(100)

		splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
		splitter.addWidget(pattern_text_area)
		splitter.addWidget(loading_log_area)


		left_btns_grid_box = QtWidgets.QGridLayout()
		left_btns_grid_box.addWidget(btn_expand_all, 0, 0)
		left_btns_grid_box.addWidget(btn_collapse_all, 0, 1)

		vertical_box = QtWidgets.QVBoxLayout()
		vertical_box.setSpacing(0)
		vertical_box.addWidget(splitter)
		vertical_box.addLayout(top_btns_grid_box)
		vertical_box.addLayout(bottom_btns_grid_box)

		left_vertical_box = QtWidgets.QVBoxLayout()
		left_vertical_box.setSpacing(0)
		left_vertical_box.addWidget(patterns_list)
		left_vertical_box.addLayout(left_btns_grid_box)


		horizontal_box = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		# horizontal_box.addWidget(patterns_list)
		horizontal_box.addLayout(left_vertical_box)
		horizontal_box.addLayout(vertical_box)
		# def full_path(child_ind):
		# 	if not child_ind.isValid():
		# 		return

		# 	prefix = full_path(self.model.parent(child_ind))
		# 	data = self.model.data(child_ind)

		# 	if prefix is  None:
		# 		return data
		# 	else:
		# 		return "%s/%s" % (prefix, data)

		# def _test(ind):
		# 	print(full_path(ind))

		# self.tree_view.clicked.connect(_test)

		# grid_box = QtWidgets.QGridLayout()
		# grid_box.addWidget(patterns_list, 0, 0)

		def idi_nahuy(index):
			patterns_list.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
			patterns_list.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
			patterns_list.resizeColumnToContents(0)

		patterns_list.expanded.connect(idi_nahuy)
		patterns_list.collapsed.connect(idi_nahuy)

		self.parent.setLayout(horizontal_box)

	def OnClose(self, form):
		pass

	def Show(self, caption=None, options=0):
		return idaapi.PluginForm.Show(self, caption, options=options)

"""
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
			StorageManagerForm(self.model).Show()

	@property
	def name(self):
		return 'herast:' + type(self).__name__    
"""

class ShowScriptManager(idaapi.action_handler_t):
	description = "Show manager of test's script's"
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
			StorageManagerForm().Show()

	@property
	def name(self):
		return 'test:' + type(self).__name__ 

# m = PatternStorageModel()
# action = ShowScriptManager(m)
# idaapi.register_action(idaapi.action_desc_t(action.name, action.description, action, action.hotkey))    

def __register_action(action):
		result = idaapi.register_action(
			idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
		)
		print("Registered %s with status(%x)" % (action.name, result))


class UnregisterAction(idaapi.action_handler_t):
	description = "test"
	hotkey = 'Ctrl+Shift+E'

	def __init__(self, action):
		super(UnregisterAction, self).__init__()
		self.target_name = action.name

	def update(self, ctx):
		return True

	def activate(self, ctx):
		print("[*] Unregistered %s with status(%x)" % (self.target_name, idaapi.unregister_action(self.target_name)))

	@property
	def name(self):
		return 'test:' + type(self).__name__ 


def main():
	__register_action(ShowScriptManager())
	__register_action(UnregisterAction(ShowScriptManager()))

main()