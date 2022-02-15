import idaapi
import idc

import importlib
import importlib.util

from typing import List

import os
import glob
import traceback
import json

from PyQt5 import QtCore, QtGui


def load_storage_module_from_file(path):
	spec = importlib.util.spec_from_file_location("module", path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	if not hasattr(module, "__exported"):
		return None
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

"""
def singleton(cls):
	instances = {}
	def getinstance(*args, **kwargs):
		if cls not in instances:
			instances[cls] = cls(*args, **kwargs)
		return instances[cls]
	return getinstance


@singleton
class StorageManager(QtCore.QAbstractListModel):
	ARRAY_NAME = "$herast:PatternStorage"
	DEFAULT_DIRECTORY = "ready_patterns"
	
	def __init__(self, directory_path=DEFAULT_DIRECTORY, *args):
		super().__init__(*args)
		self.schemes_storages: List(SchemesStorage) = list()
		self.directory = os.path.join(os.path.dirname(__file__), directory_path)
		# print("[*] Patterns directory: '%s'" % self.directory)

		self._load_schemes()

	# Qt overload
	def rowCount(self, parent):
		return len(self.schemes_storages)

	def data(self, index, role):
		if not index.isValid():
			return QtCore.QVariant()

		if index.row() >= len(self.schemes_storages):
			return QtCore.QVariant()

		pat = self.schemes_storages[index.row()]

		if role == QtCore.Qt.DisplayRole:
			return QtCore.QVariant(pat.filename)

		elif role == QtCore.Qt.BackgroundRole:
			if pat.error:
				return _color_with_opacity(QtCore.Qt.red)
			elif pat.enabled:
				return _color_with_opacity(QtCore.Qt.green)
			else:
				return _color_with_opacity(QtCore.Qt.gray)
		else:
			return QtCore.QVariant()

	# def dataChanged(self):
	#     pass

	# Helper functions
	def _load_schemes(self):
		stored_string = load_long_str_from_idb(self.ARRAY_NAME) or '[]'
		stored_enabled_array = json.loads(stored_string)
		enabled_presented_on_fs = list()

		for file_path in glob.iglob(self.directory + '/*.py'):
			basename = os.path.basename(file_path)
			if basename in stored_enabled_array:
				enabled_presented_on_fs.append(basename)
				try:
					m = load_module_from_file(file_path)
					exports_assert(m)
					enabled = True
					error = False
					log = "Enabled!"
				except Exception as e:
					m = None
					enabled = False
					error = False
					log = traceback.format_exc()
			else:
				m = None
				enabled = False
				error = False
				log = "Disabled!"
			
			self.schemes_storages.append(SchemesStorage(file_path, m, enabled, error, log))

		if len(stored_enabled_array) != 0 and len(enabled_presented_on_fs) != len(stored_enabled_array):
				print("[!] Some of patterns stored inside IDB missing on fs, they will be excluded from IDB.")
				save_long_str_to_idb(self.ARRAY_NAME, json.dumps(enabled_presented_on_fs))

	def disable_storage(self, indices):
		for qindex in indices:
			row = qindex.row()
			self.schemes_storages[row].disable()
			self.dataChanged.emit(qindex, qindex)
		self.sync_idb_array()

	def enable_storage(self, indices):
		for qindex in indices:
			row = qindex.row()
			self.schemes_storages[row].enable()
			self.dataChanged.emit(qindex, qindex)
		self.sync_idb_array()

	def reload_storage(self, indices):
		for qindex in indices:
			row = qindex.row()
			if not self.schemes_storages[row].reload():
				del self.schemes_storages[row]
			self.dataChanged.emit(qindex, qindex)
			self.sync_idb_array()

	def disable_all_storages(self):
		for i, p in enumerate(self.schemes_storages):
			p.disable()
			qindex = self.index(i)
			self.dataChanged.emit(qindex, qindex)
		self.sync_idb_array()

	def refresh_storages(self):
		self.schemes_storages = list()
		self._load_schemes()
		self.dataChanged.emit(self.index(0), self.index(len(self.schemes_storages)))

	def sync_idb_array(self):
		new_array_to_store = [p.filename for p in self.schemes_storages if p.enabled]
		save_long_str_to_idb(self.ARRAY_NAME, json.dumps(new_array_to_store))
"""


class SchemesStorage:
	def __init__(self, path, module, enabled, error, log):
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
				self.enabled = True

	def disable(self):
		if not self.enabled:
			return

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

	ARRAY_NAME = "$herast:PatternStorage"
	stored_string = load_long_str_from_idb(ARRAY_NAME) or '[]'
	stored_enabled_array = json.loads(stored_string)
	is_enabled = filename in stored_enabled_array

	storage = SchemesStorage(filename, module, is_enabled, True, "Disabled!")
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

			parent_item.children.append(SchemeStorageTreeItem([basename], SchemeStorageTreeItem.TYPE_FILE, parent=parent_item))

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

def get_enabled_storages():
	return [s for s in schemes_storages.values() if s.enabled]