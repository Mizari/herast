# Terminology

- Pattern is a way to describe part of decompiled AST. Patterns are further described in [patterns documentation](https://github.com/mostobriv/herast/tree/main/documentation/patterns.md)
- Scheme is a way to handle found patterns in decompiled functions. Schemes are further described in [schemes documentation](https://github.com/mostobriv/herast/tree/main/documentation/schemes.md)
- Storage is a module, that can export schemes to herast.
- Enabled storage is a storage, that passive matcher will load and import schemes from.
- Enabled scheme is a imported scheme, that will be automatically applied by passive matcher during every decompilation.
- Matcher is an object, that applies schemes to functions.

## herapi

herapi is designed for safe "import * from herapi". In order to get more information for herapi entries use help(herapi.FUNCTION_OR_CLASS).
 Use herapi.herapi_help() or heraip.herapi_help_patterns() instead of help(herapi), since herapi only imports from others.  

## Schemes Storages View

Actions of schemes storages view are for in-IDB settings only. In order to do actions globally currently it is required to use herapi.  

- Disable: disables selected storage.
- Enable: enables selected storage.
- Reload: reload selected storage module.
- Add File: add new storage module to current IDB.
- Add Folder: add new folder with storage modules to current IDB.
- Remove File: remove selected storage module from current IDB.
- Remove Folder: remove selected folder with storage modules from current IDB.
- Refresh all: refresh GUI view.
- Disable all: disable all storages.

## Settings

There are two ways to configure settings: globally in C:\Users\USERNAME\AppData\Roaming\Hex-Rays\IDA Pro\herast_settings.json or in specific IDB "$herast:PatternStorage" netnode. IDB settings overwrite global.  

- Storage folders: folders with schemes storages. Every .py file from folders will be imported with expectation of herapi.register_storage_scheme() calls.
- Storage files: specific python modules, that will be imported with expectation of herapi.register_storage_scheme() calls.
- Storage statuses: "enabled" or "disabled" for each storage module. Enabled means schemes will be loaded and used, disabled means otherwise.
- Matching time: debug flag for calculating time spent on schemes matching. Turned off by default.
