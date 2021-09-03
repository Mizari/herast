import idaapi
import idc

import importlib
import importlib.util

import os
import glob
import traceback
import json

idaapi.require('tree.consts')
from tree.consts import ReadyPatternState

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

def singleton(cls):
    instances = {}
    def getinstance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return getinstance

@singleton
class PatternStorageModel(QtCore.QAbstractListModel):
    ARRAY_NAME = "$herast:PatternStorage"
    DEFAULT_DIRECTORY = "ready_patterns"
    
    def __init__(self, directory_path=DEFAULT_DIRECTORY, *args):
        super().__init__(*args)
        self.ready_patterns = list()
        self.directory = os.path.join(os.path.dirname(__file__), directory_path)
        print("[*] Patterns directory: '%s'" % self.directory)

        self._load_patterns()
    
    # Qt overload
    def rowCount(self, parent):
        return len(self.ready_patterns)

    def data(self, index, role):
        if not index.isValid():
            return QtCore.QVariant()

        if index.row() >= len(self.ready_patterns):
            return QtCore.QVariant()

        pat = self.ready_patterns[index.row()]

        if role == QtCore.Qt.DisplayRole:
            return QtCore.QVariant(pat.filename)

        elif role == QtCore.Qt.BackgroundRole:
            if pat.state == ReadyPatternState.ENABLED:
                return _color_with_opacity(QtCore.Qt.green)
            elif pat.state == ReadyPatternState.ERROR:
                return _color_with_opacity(QtCore.Qt.red)
            elif pat.state == ReadyPatternState.DISABLED:
                return _color_with_opacity(QtCore.Qt.gray)
        else:
            return QtCore.QVariant()

    def dataChanged(self):
        pass

    # Helper functions
    def _load_patterns(self):
        stored_string = load_long_str_from_idb(self.ARRAY_NAME) or b'[]'
        stored_enabled_array = json.loads(stored_string)
        if len(stored_enabled_array) == 0:
            self._cold_load_patterns()

        else:
            available_files = list(glob.glob(self.directory + '/*.py'))
            available_basenames = [os.path.basename(full_path) for full_path in available_files]
            tmp = list(filter(lambda x: x in available_basenames, stored_enabled_array))
            if len(tmp) != stored_enabled_array:
                print("[!] Missing some of patterns stored inside IDB, they was excluded.")
        
    def _cold_load_patterns(self):
        print("[*] No patterns were stored inside IDB, performing cold init.")

        for file_path in glob.glob(self.directory + '/*.py'):
            try:
                m = load_module_from_file(file_path)
                state = ReadyPatternState.DISABLED
                log = "Success!"
            except Exception as e:
                m = None
                state = ReadyPatternState.ERROR
                log = traceback.format_exc()
            finally:
                self.ready_patterns.append(ReadyPattern(file_path, m, state, log))
        
    def disable_pattern(self, indices):
        for qindex in indices:
            if self.ready_patterns[qindex.row()].state != ReadyPatternState.ERROR:
                self.ready_patterns[qindex.row()].state = ReadyPatternState.DISABLED

    def enable_pattern(self, indices):
        for qindex in indices:
            if self.ready_patterns[qindex.row()].state != ReadyPatternState.ERROR:
                self.ready_patterns[qindex.row()].state = ReadyPatternState.ENABLED

    def reload_pattern(self, indices):
        for qindex in indices:
            if not self.ready_patterns[qindex.row()].reload():
                del self.ready_patterns[qindex.row()]
                # emit here that data was changed

    def disable_all_patterns(self):
        for p in self.ready_patterns:
            if p.state == ReadyPatternState.ENABLED:
                p.state = ReadyPatternState.DISABLED
                # emit here that data was changed


    def reload_all_patterns(self):
        pass


class IDBStoring:
    ARRAY_NAME = "$herast:PatternStorage"

    def __init__(self):
        self.__patterns = list()

        self.__load()

    def put(self, pattern_name):
        self.__patterns.append(pattern_name)

        self.__save()

    def remove(self, pattern_name):
        if pattern_name in self.__patterns:
            idx = self.__patterns.index(pattern_name)
            del self.__patterns[idx]

        self.__save()

    def __save(self):
        if len(self.__patterns) > 0:
            save_long_str_to_idb(self.ARRAY_NAME, json.dumps(self.__patterns))

    def __load(self):
        stored_string = load_long_str_from_idb(self.ARRAY_NAME)
        if stored_string is not None:
            self.__patterns = json.loads(stored_string)


class ReadyPattern:
    def __init__(self, path, module, state, log):
        self.path = path
        self.filename = os.path.basename(path)
        self.module = module
        self.state = state
        self.log = log
        self.source = str()

        if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
            with open(self.path, 'r') as f:
                self.source = f.read()
        

    def reload(self):
        if os.path.isfile(self.path):
            try:
                self.module = load_module_from_file(self.path)
            except Exception as e:
                self.module = None
                self.state = ReadyPatternState.ERROR
                self.log = traceback.format_exc()
            
            with open(self.path, 'r') as f:
                self.source = f.read()

            return True
        else:
            return False
