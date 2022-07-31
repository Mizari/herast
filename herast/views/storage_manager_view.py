from PyQt5 import QtCore, QtWidgets, QtGui

import idaapi
import os
import glob

import herast.passive_manager as passive_manager


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

class StorageManagerModel(QtCore.QAbstractItemModel):
	def __init__(self):
		super().__init__()
		self.root = SchemeStorageTreeItem(["File"])
		self.folders = []
		self.files = []
		self.storages_list = None

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
		if parent_item is None:
			return QtCore.QModelIndex()

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

	def get_storage_path_by_index(self, idx):
		item = self.get_item(idx)
		return item.fullpath

	def get_storage_by_index(self, idx):
		fullpath = self.get_storage_path_by_index(idx)
		if fullpath is None:
			return None
		return passive_manager.get_storage(fullpath)

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

	def refresh_view(self):
		self.storages_list.reset()
	
	def refresh_all(self):
		self.root = SchemeStorageTreeItem(["File"])
		folders = self.folders
		files = self.files

		self.files = []
		self.folders = []
		for folder in folders:
			self.add_folder(folder)

		for file in files:
			self.add_file(file)
	
		self.refresh_view()
	
	def disable_all(self):
		print("disabling all is not yet implemented")
	
	def add_folder(self, storage_folder: str = None):
		if storage_folder is None:
			storage_folder = idaapi.ask_text(1024, None, "Enter storages folder")

		if storage_folder in self.folders:
			return

		self.folders.append(storage_folder)

		parent_item = self.root
		folder_part = storage_folder
		while True:
			for child in parent_item.children:
				child_data = child.data(SchemeStorageTreeItem.FILENAME_COLUMN)
				if folder_part.startswith(child_data):
					parent_item = child
					break
			else:
				child = SchemeStorageTreeItem([folder_part], SchemeStorageTreeItem.TYPE_DIRECTORY, parent=parent_item)
				parent_item.children.insert(0, child) # keeps directories at the top of view
				folder_item = child
				break

		for full_path in glob.iglob(storage_folder + '/**/**.py', recursive=True):
			storage = passive_manager.get_storage(full_path)
			if storage is None:
				continue

			relative_path = os.path.relpath(full_path, start=storage_folder)
			splited_path = relative_path.split(os.sep)
			basename = splited_path.pop()
			assert os.path.basename(full_path) == basename, "Extracted basename doesn't match with actual basename"

			parent_item = folder_item
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
			file_item.enabled = storage.enabled
			parent_item.children.append(file_item)
	
		self.refresh_view()

	def add_file(self, file_path: str = None):
		if file_path is None:
			file_path = idaapi.ask_file(False, None, "Enter storage file")
	
		if file_path in self.files:
			print("Already have this file", file_path)
			return

		passive_manager.add_storage_file(file_path)

		file_item = SchemeStorageTreeItem([file_path], SchemeStorageTreeItem.TYPE_FILE, parent=self.root)
		file_item.fullpath = file_path
		file_item.enabled = False
		self.root.children.append(file_item)
		self.files.append(file_path)
		self.refresh_view()

	def remove_file(self, indices):
		if len(indices) != 1:
			print("Got weird number of selected files, returning")
			return

		qidx = indices[0]
		item = self.get_item(qidx)
		if item is None:
			print("Failed to get tree item, returning")
			return

		file_path = item._data[0]
		if file_path not in self.files:
			print("Selected item is not file, returning")
			return

		passive_manager.remove_storage_file(file_path)
		self.files.remove(file_path)
		self.refresh_view()

	def remove_folder(self, indices):
		if len(indices) != 1:
			print("Got weird number of selected folders, returning")
			return

		qidx = indices[0]
		item = self.get_item(qidx)
		if item is None:
			print("Failed to get tree item, returning")
			return

		folder_path = item._data[0]
		if folder_path not in self.folders:
			print("Selected item is not folder, returning")
			return

		passive_manager.remove_storage_folder(folder_path)
		self.folders.remove(folder_path)
		self.refresh_view()

	def disable_storage(self, indices):
		for qindex in indices:
			storage_path = self.get_storage_path_by_index(qindex)
			if storage_path is not None:
				passive_manager.disable_storage(storage_path)
				item = self._get_file_item_by_index(qindex)
				if item is not None:
					item.disable()
					self.dataChanged.emit(qindex, qindex)

	def enable_storage(self, indices):
		for qindex in indices:
			storage_path = self.get_storage_path_by_index(qindex)
			if storage_path is not None:
				passive_manager.enable_storage(storage_path)
				item = self._get_file_item_by_index(qindex)
				if item is not None:
					item.enable()
					self.dataChanged.emit(qindex, qindex)

	def reload_storage(self, indices):
		for qindex in indices:
			storage_path = self.get_storage_path_by_index(qindex)
			if storage_path is not None:
				passive_manager.reload_storage(storage_path)
				self.dataChanged.emit(qindex, qindex)

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
		self.model = StorageManagerModel()
		self.init_ui(self.model)
		for storage_folder in passive_manager.get_storages_folders():
			self.model.add_folder(storage_folder)

	def init_ui(self, model: StorageManagerModel):
		self.parent.resize(400, 600)
		self.parent.setWindowTitle("HeRAST Schemes Storages View")

		def update_storage_data(idx=None):
			if idx is None:
				idxs = storages_list.selectedIndexes()
				if len(idxs) == 0:
					return
				idx = idxs[0]

			storage = model.get_storage_by_index(idx)
			if storage is None: return

			source_text = storage.get_source()
			if source_text is None:
				source_text = "Failed to read source text"

			status_text = storage.get_status()
			storage_source_area.setPlainText(source_text)
			loading_log_area.setPlainText(status_text)

		storages_list = QtWidgets.QTreeView()
		storages_list.setModel(model)
		storages_list.setItemDelegate(BoldDelegate())
		storages_list.setMaximumWidth(300)
		storages_list.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
		storages_list.horizontalScrollBar().setEnabled(True)
		# self.tree_view.setSortingEnabled(True)
		storages_list.selectionModel().currentChanged.connect(lambda cur, prev: update_storage_data(cur))
		storages_list.model().dataChanged.connect(lambda : update_storage_data())
		storages_list.setCurrentIndex(storages_list.model().index(0, 0, QtCore.QModelIndex()))
		model.storages_list = storages_list

		class ModelButton(QtWidgets.QPushButton):
			def __init__(self, name, callback=None):
				super().__init__(name)
				if callback is not None:
					self.clicked.connect(callback)

		btn_reload       = ModelButton("&Reload",       lambda: model.disable_storage(storages_list.selectedIndexes()))
		btn_enable       = ModelButton("&Enable",       lambda: model.enable_storage(storages_list.selectedIndexes()))
		btn_disable      = ModelButton("&Disable",      lambda: model.disable_storage(storages_list.selectedIndexes()))
		btn_refresh_all  = ModelButton("Refresh all",   lambda: model.refresh_all())
		btn_disable_all  = ModelButton("Disable All",   lambda: model.disable_all())
		btn_add_file     = ModelButton("Add File",      lambda: model.add_file())
		btn_add_folder   = ModelButton("Add Folder",    lambda: model.add_folder())
		btn_del_file     = ModelButton("Remove File",   lambda: model.remove_file(storages_list.selectedIndexes()))
		btn_del_folder   = ModelButton("Remove Folder", lambda: model.remove_folder(storages_list.selectedIndexes()))
		btn_expand_all   = ModelButton("Expand all",   storages_list.expandAll)
		btn_collapse_all = ModelButton("Collapse all", storages_list.collapseAll)

		class GridLayout(QtWidgets.QGridLayout):
			def __init__(self, *buttons):
				super().__init__()
				for b_id, b in enumerate(buttons):
					self.addWidget(b, 0, b_id)

		bottom_btns_grid_box = GridLayout(btn_refresh_all, btn_disable_all)
		middle_btns_grid_box = GridLayout(btn_add_file, btn_add_folder, btn_del_file, btn_del_folder)
		top_btns_grid_box    = GridLayout(btn_disable, btn_enable, btn_reload)
		left_btns_grid_box   = GridLayout(btn_expand_all, btn_collapse_all)

		storage_source_area = QtWidgets.QTextEdit()
		storage_source_area.setTabStopDistance(QtGui.QFontMetricsF(storage_source_area.font()).width(' ') * 4)
		storage_source_area.setTabStopWidth(4)
		storage_source_area.setReadOnly(True)

		loading_log_area = QtWidgets.QTextEdit()
		loading_log_area.setReadOnly(True)
		loading_log_area.setMaximumHeight(100)

		splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
		splitter.addWidget(storage_source_area)
		splitter.addWidget(loading_log_area)

		class VboxLayout(QtWidgets.QVBoxLayout):
			def __init__(self, widget, *layouts) -> None:
				super().__init__()
				self.setSpacing(0)
				self.addWidget(widget)
				for l in layouts:
					self.addLayout(l)

		vertical_box = VboxLayout(splitter, top_btns_grid_box, middle_btns_grid_box, bottom_btns_grid_box)
		left_vertical_box = VboxLayout(storages_list, left_btns_grid_box)

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
