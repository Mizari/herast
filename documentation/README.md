# Terminology
- Pattern is a way to describe part of decompiled AST. Patterns are further described in https://github.com/mostobriv/herast/tree/main/documentation/patterns.md
- Scheme is a way to handle found patterns in decompiled functions. Schemes are further described in https://github.com/mostobriv/herast/tree/main/documentation/schemes.md
- Storage is a module, that exports schemes to herast.
- Matcher is an object, that applies schemes to functions.


# Settings
There are two ways to configure settings: globally in C:\Users\USERNAME\AppData\Roaming\Hex-Rays\IDA Pro\herast_settings.json or in specific IDB "$herast:PatternStorage" netnode. IDB settings overwrite global.  
- Storage folders: folders with schemes storages. Every .py file from folders will be imported with expectation of herapi.register_storage_scheme() calls.
- Storage files: specific python modules, that will be imported with expectation of herapi.register_storage_scheme() calls.
- Storage statuses: "enabled" or "disabled" for each storage module. Enabled means schemes will be loaded and used, disabled means otherwise.
- Matching time: debug flag for calculating time spent on schemes matching. Turned off by default.