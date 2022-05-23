from PyQt5 import QtCore, QtWidgets, QtGui
from herast.tree.utils import singleton

import idaapi
import os
import glob

import herast.storage_manager as storage_manager

from typing import Optional


def _color_with_opacity(tone, opacity=160):
	color = QtGui.QColor(tone)
	color.setAlpha(opacity)
	return color

class SchemeStorageTreeItem:
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
		self.fullpath = None
		self.enabled = False

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

	def enable(self):
		self.enabled = True

	def disable(self):
		self.enabled = False

	def is_enabled(self):
		if self.is_file() and self.enabled:
			return True
		else:
			return False

@singleton
class StorageManagerModel(QtCore.QAbstractItemModel):
	def __init__(self):
		super().__init__()
		self.root = SchemeStorageTreeItem(["File"])
		for storage_folder in storage_manager.storages_folders:
			self.__add_folder(storage_folder)

	def __add_folder(self, storage_folder):
		for full_path in glob.iglob(storage_folder + '/**/**.py', recursive=True):
			if storage_manager.get_storage(full_path) is None:
				continue

			relative_path = os.path.relpath(full_path, start=storage_folder)
			splited_path = relative_path.split(os.sep)
			basename = splited_path.pop()
			assert os.path.basename(full_path) == basename, "Extracted basename doesn't match with actual basename"

			parent_item = self.root
			for part in splited_path:
				for child in parent_item.children:
					if part == child.data(SchemeStorageTreeItem.FILENAME_COLUMN):
						parent_item = child
						break
				else:
					child = SchemeStorageTreeItem([part], SchemeStorageTreeItem.TYPE_DIRECTORY, parent=parent_item)
					parent_item.children.insert(0, child) # keeps directories at the top of view
					parent_item = child

			file_item = SchemeStorageTreeItem([basename], SchemeStorageTreeItem.TYPE_FILE, parent=parent_item)
			file_item.fullpath = full_path
			parent_item.children.append(file_item)

	def index(self, row, column, parent_index):
		if not self.hasIndex(row, column, parent_index):
			return QtCore.QModelIndex()

		parent_item = parent_index.internalPointer() if parent_index.isValid() else self.root

		child_item = parent_item.child(row)

		if child_item:
			return self.createIndex(row, column, child_item)

		return QtCore.QModelIndex()
	
	def get_item(self, index):
		return index.internalPointer()

	# TODO: consider about adding hints via QtCore.Qt.ToolTipRole
	def data(self, index, role=QtCore.Qt.DisplayRole):
		if not index.isValid():
			return QtCore.QVariant()

		if role == QtCore.Qt.BackgroundRole:
			item = self.get_item(index)
			if item is None or item.is_directory():
				return QtCore.QVariant()
		
			if item.is_file() and item.is_enabled():
				return _color_with_opacity(QtCore.Qt.green)
			else:
				return _color_with_opacity(QtCore.Qt.gray, opacity=80)

		if role != QtCore.Qt.DisplayRole:
			return QtCore.QVariant()

		item: SchemeStorageTreeItem = self.get_item(index)

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

	def get_storage_by_index(self, idx):
		item = self.get_item(idx)
		if item.fullpath is None:
			return None
		return storage_manager.get_storage(item.fullpath)

	def _get_item_by_index(self, idx):
		item = self.get_item(idx)
		if item.fullpath is None:
			return None

		return item

	def _get_file_item_by_index(self, idx):
		item = self._get_item_by_index(idx)
		if item is None or not item.is_file():
			return None
		
		return item

	def disable_storage(self, indices):
		for qindex in indices:
			storage = self.get_storage_by_index(qindex)
			if storage is not None:
				storage.disable()
				item = self._get_file_item_by_index(qindex)
				if item is not None:
					item.disable()
					self.dataChanged.emit(qindex, qindex)

	def enable_storage(self, indices):
		for qindex in indices:
			storage = self.get_storage_by_index(qindex)
			if storage is not None:
				storage.enable()
				item = self._get_file_item_by_index(qindex)
				if item is not None:
					item.enable()
					self.dataChanged.emit(qindex, qindex)

	def reload_storage(self, indices):
		for qindex in indices:
			storage = self.get_storage_by_index(qindex)
			if storage is not None:
				storage.reload()

	# def flags(self, index):
	# 	if not index.isValid():
	# 		return QtCore.Qt.NoItemFlags

	# 	return QtCore.QAbstractItemModel.flags(index)


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
		self.parent.setWindowTitle("HeRAST Schemes Storages View")

		self.model = StorageManagerModel()
		# self.model = QtGui.QStandardItemModel()
		# self.model.setHorizontalHeaderLabels(["Name"])

		storages_list = QtWidgets.QTreeView()
		storages_list.setModel(self.model)
		storages_list.setItemDelegate(BoldDelegate())
		# self.tree_view.setSortingEnabled(True)

		btn_reload = QtWidgets.QPushButton("&Reload")
		btn_enable = QtWidgets.QPushButton("&Enable")
		btn_disable = QtWidgets.QPushButton("&Disable")
		btn_refresh_all = QtWidgets.QPushButton("Refresh all")
		btn_disable_all = QtWidgets.QPushButton("Disable All")

		btn_expand_all = QtWidgets.QPushButton("Expand all")
		btn_collapse_all = QtWidgets.QPushButton("Collapse all")

		btn_expand_all.clicked.connect(storages_list.expandAll)
		btn_collapse_all.clicked.connect(storages_list.collapseAll)

		storages_list.setMaximumWidth(storages_list.size().width() // 3)
		storages_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

		storages_list.horizontalScrollBar().setEnabled(True)

		bottom_btns_grid_box = QtWidgets.QGridLayout()
		bottom_btns_grid_box.addWidget(btn_refresh_all, 0, 0)
		bottom_btns_grid_box.addWidget(btn_disable_all, 0, 1)

		top_btns_grid_box = QtWidgets.QGridLayout()
		top_btns_grid_box.addWidget(btn_disable, 0, 0)
		top_btns_grid_box.addWidget(btn_enable, 0, 1)
		top_btns_grid_box.addWidget(btn_reload, 0, 2)

		btn_disable.clicked.connect(lambda: storages_list.model().disable_storage(storages_list.selectedIndexes()))
		btn_enable.clicked.connect(lambda: storages_list.model().enable_storage(storages_list.selectedIndexes()))
		btn_reload.clicked.connect(lambda: storages_list.model().reload_storage(storages_list.selectedIndexes()))

		storage_source_area = QtWidgets.QTextEdit()
		# storage_source_area.setTabStopDistance(QtGui.QFontMetricsF(storage_source_area.font()).width(' ') * 4)
		storage_source_area.setTabStopWidth(4)
		storage_source_area.setReadOnly(True)

		loading_log_area = QtWidgets.QTextEdit()
		loading_log_area.setReadOnly(True)
		loading_log_area.setMaximumHeight(100)

		splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
		splitter.addWidget(storage_source_area)
		splitter.addWidget(loading_log_area)

		def update_storage_data(idx=None):
			if idx is None:
				idxs = storages_list.selectedIndexes()
				if len(idxs) == 0:
					return
				idx = idxs[0]

			storage = self.model.get_storage_by_index(idx)
			if storage is None: return

			source_text = storage.get_source()
			if source_text is None:
				source_text = "Failed to read source text"

			status_text = storage.get_status()
			storage_source_area.setPlainText(source_text)
			loading_log_area.setPlainText(status_text)

		storages_list.selectionModel().currentChanged.connect(lambda cur, prev: update_storage_data(cur))
		storages_list.model().dataChanged.connect(lambda : update_storage_data())
		storages_list.setCurrentIndex(storages_list.model().index(0, 0, QtCore.QModelIndex()))

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
		left_vertical_box.addWidget(storages_list)
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

		def foo(index):
			storages_list.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
			storages_list.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
			storages_list.resizeColumnToContents(0)

		storages_list.expanded.connect(foo)
		storages_list.collapsed.connect(foo)

		self.parent.setLayout(horizontal_box)

	def OnClose(self, form):
		self.model.dataChanged.disconnect()

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
