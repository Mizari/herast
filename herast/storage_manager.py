import idaapi
import idc

import os
import glob
import traceback
import json

from PyQt5 import QtCore, QtGui

from .tree.utils import save_long_str_to_idb
from .tree.utils import load_long_str_from_idb
from .tree.utils import load_python_module_from_file


def load_storage_module_from_file(path):
	module = load_python_module_from_file(path)
	if not hasattr(module, "__exported"):
		return None
	return module

ARRAY_NAME = "$herast:PatternStorage"
def get_enabled_idb_storages():
	stored_string = load_long_str_from_idb(ARRAY_NAME) or '[]'
	stored_enabled_array = json.loads(stored_string)
	return stored_enabled_array

def save_enabled_idb_storages(stored_enabled_array):
	save_long_str_to_idb(ARRAY_NAME, json.dumps(stored_enabled_array))

def _color_with_opacity(tone, opacity=160):
	color = QtGui.QColor(tone)
	color.setAlpha(opacity)
	return color

class SchemesStorage:
	def __init__(self, path, module, enabled, error=False, log="Enabled!"):
		self.path = path
		self.filename = os.path.basename(path)
		self.module = module
		self.enabled = enabled
		self.error = error
		self.log = log
		self.source = str()

		if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
			with open(self.path, 'r') as f:
				self.source = f.read()

	def enable(self):
		if self.enabled:
			return

		if not self.error:
			self.log = "Enabled!"
			if self.module is None:
				assert self.reload()
			if not self.error:
				stored_enabled_array = get_enabled_idb_storages()
				stored_enabled_array.append(self.path)
				save_enabled_idb_storages(stored_enabled_array)
				self.enabled = True

	def disable(self):
		if not self.enabled:
			return

		stored_enabled_array = get_enabled_idb_storages()
		if self.path in stored_enabled_array:
			stored_enabled_array.remove(self.path)
		save_enabled_idb_storages(stored_enabled_array)
		self.enabled = False
		if not self.error:
			self.log = "Disabled!"

	def reload(self):
		if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
			try:
				del self.module
				self.module = load_storage_module_from_file(self.path)
				self.error = False
			except Exception as e:
				self.module = None
				self.error = True
				self.enabled = False
				self.log = traceback.format_exc()
			
			with open(self.path, 'r') as f:
				self.source = f.read()

			return True
		else:
			return False

schemes_storages = {}

storages_folders = set()
default_storage_dir = os.path.dirname(__file__) + "\\ready_patterns\\"
if os.path.exists(default_storage_dir):
	storages_folders.add(default_storage_dir)
storages_files = set()

def load_all_storages():
	for folder in storages_folders:
		load_storage_folder(folder)
	for file in storages_files:
		load_storage_file(file)

def load_storage_folder(folder_name):
	for full_path in glob.iglob(folder_name + '/**/**.py', recursive=True):
		load_storage_file(full_path)

def load_storage_file(filename):
	module = load_storage_module_from_file(filename)
	if module is None:
		return False

	is_enabled = filename in get_enabled_idb_storages()
	storage = SchemesStorage(filename, module, is_enabled)
	schemes_storages[filename] = storage
	return True

def get_storage(filename):
	return schemes_storages.get(filename, None)

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


class StorageManager(QtCore.QAbstractItemModel):
	def __init__(self):
		super().__init__()
		self.root = SchemeStorageTreeItem(["File"])
		for storage_folder in storages_folders:
			self.__add_folder(storage_folder)

	def __add_folder(self, storage_folder):
		for full_path in glob.iglob(storage_folder + '/**/**.py', recursive=True):
			if get_storage(full_path) is None:
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

		if role != QtCore.Qt.DisplayRole:
			return QtCore.QVariant()

		item = self.get_item(index)

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
	
	def get_storage_by_index(self, idx):
		item = self.get_item(idx)
		if item.fullpath is None:
			return None
		return get_storage(item.fullpath)

	def disable_storage(self, indices):
		for qindex in indices:
			storage = self.get_storage_by_index(qindex)
			if storage is not None:
				storage.disable()

	def enable_storage(self, indices):
		for qindex in indices:
			storage = self.get_storage_by_index(qindex)
			if storage is not None:
				storage.enable()

	def reload_storage(self, indices):
		for qindex in indices:
			storage = self.get_storage_by_index(qindex)
			if storage is not None:
				storage.reload()

	# def flags(self, index):
	# 	if not index.isValid():
	# 		return QtCore.Qt.NoItemFlags

	# 	return QtCore.QAbstractItemModel.flags(index)

def get_enabled_storages():
	return [s for s in schemes_storages.values() if s.enabled]