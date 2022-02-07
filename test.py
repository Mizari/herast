from PyQt5 import QtCore, QtWidgets, QtGui, Qt

import idaapi

import os
import glob
import json


def load_module_from_file(path):
	spec = importlib.util.spec_from_file_location("module", path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def save_long_str_to_idb(array_name, value):
	""" Overwrites old array completely in process """
	id = idc.get_array_id(array_name)
	if id != -1:
		idc.delete_array(id)
	id = idc.create_array(array_name)
	r = []
	for idx in range(len(value) // 1024 + 1):
		s = value[idx * 1024: (idx + 1) * 1024]
		r.append(s)
		idc.set_array_string(id, idx, s)


def load_long_str_from_idb(array_name):
	id = idc.get_array_id(array_name)
	if id == -1:
		return None
	max_idx = idc.get_last_index(idc.AR_STR, id)
	result = [idc.get_array_element(idc.AR_STR, id, idx) for idx in range(max_idx + 1)]
	return b"".join(result).decode("utf-8")


def _color_with_opacity(tone, opacity=160):
	color = QtGui.QColor(tone)
	color.setAlpha(opacity)
	return color

class PatternStorageTreeItem:
	FILENAME_COLUMN = 0
	DESCRIPTION_COLUMN = 1

	TYPE_HEADER = 0
	TYPE_DIRECTORY = 1
	TYPE_FILE = 2

	def __init__(self, data, type=TYPE_HEADER, parent=None):
		self._data = data # columns of curent file
		self.children = list() # files in directory

		self.type = type

		self.parent = parent 

	def parentItem(self):
		return self.parent

	def child(self, row):
		if row < 0 or row >= len(self.children):
			return None

		return self.children[row]

	def columnCount(self):
		if type(self._data) is list:
			return len(self._data)

		return 1

	def childrenCount(self):
		return len(self.children)

	def row(self):
		if self.parent:
			return self.parent.children.index(self)
		return 0

	def data(self, column):
		if column < 0 or column >= len(self._data):
			return QtCore.QVariant()

		return self._data[column]

	def is_directory(self):
		return self.type == self.TYPE_DIRECTORY

	def is_file(self):
		return not self.is_directory()

class BoldDelegate(QtWidgets.QStyledItemDelegate):
	def paint(self, painter, option, index):
		if not index.isValid():
			return 

		if index.internalPointer().is_directory():
			option.font.setWeight(QtGui.QFont.Bold)
		QtWidgets.QStyledItemDelegate.paint(self, painter, option, index)

		  
class PatternStorageModel(QtCore.QAbstractItemModel):
	DEFAULT_DIRECTORY = "ready_patterns"

	def __init__(self):
		super().__init__()
		self.root = PatternStorageTreeItem(["File"])
		self.directory = os.path.join(os.path.dirname('D:\\Share\\git-stuff\\herast\\huy.txt'), self.DEFAULT_DIRECTORY)

		self.__populate()

	def __populate(self):
		for full_path in glob.iglob(self.directory + '/**/**.py', recursive=True):
			relative_path = os.path.relpath(full_path, start=self.directory)

			splited_path = relative_path.split(os.sep)
			basename = splited_path.pop()
			assert os.path.basename(full_path) == basename, "Extracted basename doesn't match with actual basename"

			parent_item = self.root
			for part in splited_path:
				for child in parent_item.children:
					if part == child.data(PatternStorageTreeItem.FILENAME_COLUMN):
						parent_item = child
						break
				else:
					child = PatternStorageTreeItem([part], PatternStorageTreeItem.TYPE_DIRECTORY, parent=parent_item)
					parent_item.children.insert(0, child) # keeps directories at the top of view
					parent_item = child

			parent_item.children.append(PatternStorageTreeItem([basename], PatternStorageTreeItem.TYPE_FILE, parent=parent_item))


	def index(self, row, column, parent_index):
		if not self.hasIndex(row, column, parent_index):
			return QtCore.QModelIndex()

		parent_item = parent_index.internalPointer() if parent_index.isValid() else self.root

		child_item = parent_item.child(row)

		if child_item:
			return self.createIndex(row, column, child_item)

		return QtCore.QModelIndex()

	# TODO: consider about adding hints via QtCore.Qt.ToolTipRole
	def data(self, index, role=QtCore.Qt.DisplayRole):
		if not index.isValid():
			return QtCore.QVariant()

		if role != QtCore.Qt.DisplayRole:
			return QtCore.QVariant()

		item = index.internalPointer()

		if role == QtCore.Qt.BackgroundRole:
			if item.is_file():
				return _color_with_opacity(QtCore.Qt.Green)
			else:
				return _color_with_opacity(QtCore.Qt.gray)

		return item.data(index.column())

	def parent(self, index):
		if not index.isValid():
			return QtCore.QModelIndex()

		child_item = index.internalPointer()
		parent_item = child_item.parentItem()
		if parent_item == self.root:
			return QtCore.QModelIndex()

		return self.createIndex(parent_item.row(), 0, parent_item)

	def rowCount(self, index):
		if index.column() > 0:
			return 0

		parent_item = None
		if not index.isValid():
			parent_item = self.root
		else:
			parent_item = index.internalPointer()

		return parent_item.childrenCount()

	def columnCount(self, index):
		if index.isValid():
			return index.internalPointer().columnCount()

		return self.root.columnCount()

	def headerData(self, section, orientation, role):
		if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
			return self.root.data(section)

		return QtCore.QVariant()

	# def flags(self, index):
	# 	if not index.isValid():
	# 		return QtCore.Qt.NoItemFlags

	# 	return QtCore.QAbstractItemModel.flags(index)


class ScriptManager(idaapi.PluginForm):
	def __init__(self):
		super(ScriptManager, self).__init__()


	def OnCreate(self, form):
		self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
		self.init_ui()

	def init_ui(self):
		self.parent.resize(400, 600)
		self.parent.setWindowTitle('HUYPIZDA')

		self.model = PatternStorageModel()
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
			ScriptManager().Show()

	@property
	def name(self):
		return 'test:' + type(self).__name__ 


def __register_action(action):
		result = idaapi.register_action(
			idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
		)
		print("Registered %s with status(%x)" % (action.name, result))


def main():
	__register_action(ShowScriptManager())
	__register_action(UnregisterAction(ShowScriptManager()))

main()