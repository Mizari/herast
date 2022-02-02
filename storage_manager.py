import idaapi
import idc

import importlib
import importlib.util

import os
import glob
import traceback
import json

from PyQt5 import QtCore, QtGui


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


def exports_assert(module):
	assert hasattr(module, "__exported")


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
		self.schemes_storages = list()
		self.directory = os.path.join(os.path.dirname(__file__), directory_path)
		# print("[*] Patterns directory: '%s'" % self.directory)

		self._load_patterns()
	
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
	def _load_patterns(self):
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

	def disable_pattern(self, indices):
		for qindex in indices:
			row = qindex.row()
			self.schemes_storages[row].disable()
			self.dataChanged.emit(qindex, qindex)
		self.sync_idb_array()

	def enable_pattern(self, indices):
		for qindex in indices:
			row = qindex.row()
			self.schemes_storages[row].enable()
			self.dataChanged.emit(qindex, qindex)
		self.sync_idb_array()

	def reload_pattern(self, indices):
		for qindex in indices:
			row = qindex.row()
			if not self.schemes_storages[row].reload():
				del self.schemes_storages[row]
			self.dataChanged.emit(qindex, qindex)
			self.sync_idb_array()

	def disable_all_patterns(self):
		for i, p in enumerate(self.schemes_storages):
			p.disable()
			qindex = self.index(i)
			self.dataChanged.emit(qindex, qindex)
		self.sync_idb_array()

	def refresh_patterns(self):
		self.schemes_storages = list()
		self._load_patterns()
		self.dataChanged.emit(self.index(0), self.index(len(self.schemes_storages)))

	def sync_idb_array(self):
		new_array_to_store = [p.filename for p in self.schemes_storages if p.enabled]
		save_long_str_to_idb(self.ARRAY_NAME, json.dumps(new_array_to_store))


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
		if not self.error:
			self.log = "Enabled!"
			if self.module is None:
				assert self.reload()
			if not self.error:
				self.enabled = True

	def disable(self):
		self.enabled = False
		if not self.error:
			self.log = "Disabled!"

	def reload(self):
		if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
			try:
				del self.module
				self.module = load_module_from_file(self.path)
				exports_assert(self.module)
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
