import idaapi

import importlib
import importlib.util

import os
import glob
import traceback
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


class Loader(object):
    def __init__(self, directory_path):
        self.directory_path = directory_path
        self.enabled_patterns = PatternStorage()

        self.load_scripts()
        # self.apply_db_rules()

    # TODO: isn't it better to reuse spec inside module instead of creating a new one?
    def reload_enabled(self):
        for pat in self.enabled_patterns:
            if not pat.reload():
                # pat.enabled = False

    def enable_pattern(self, pattern_name):
        pass

    def disable_pattern(self, pattern_name):
        pass

    def load_scripts(self):
        dirpath = os.path.join(os.path.dirname(__file__), self.directory_path)
        print("Loading files from \"%s\"." % self.directory_path)

        for file_path in glob.glob(dirpath + '/*.py'):
            try:
                m = load_module_from_file(file_path)                
                print("\"%s\" successfully loaded!" % os.path.basename(file_path))
                self.loaded_modules.append(m)
            except Exception as e:
                print("Got an exception due loading of \"%s\" file: %s" % (file_path, e))
                # traceback.print_exc()



def singleton(cls):
    instances = {}

    def get_instance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return get_instance


@singleton
class PatternStorage:
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
    def __init__(self, path, module, enabled=False):
        self.path = path
        self.filename = os.path.basename(path)
        self.module = module
        self.enabled = enabled

    def reload(self):
        if os.path.isfile(self.path):
            self.module = load_module_from_file(self.path)
            return True
        else:
            return False
