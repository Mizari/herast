# herast

Rewritten for IDAPython3 (IDA_VERSION >= 7.4) version of [@groke](https://github.com/grokeus)'s [HRAST](https://github.com/sibears/hrast)


# What it does
Herast helps with finding AST subtrees and with following work with found items. Herast provides its API via herapi module and via GUI view via Shift-M hotkey. Herast is designed for easy expandability, simple reusage and for fast scripting.
<p align='center'>
<img src='pictures/storages_manager_view.png'>
</p>


# Installation
- Place `herast/` to `$IDA_DIR/python/3/` directory
- Place `herapi.py` to `$IDA_DIR/python/3/` directory
- Place `herast.py` to `$IDA_DIR/plugins` directory


# How to use
- Write [patterns](https://github.com/mostobriv/herast/tree/main/documentation/patterns.md) that describe parts of AST
- Write [schemes](https://github.com/mostobriv/herast/tree/main/documentation/schemes.md) that describe handling of found patterns
- Either export schemes to passive matcher (herapi.register_storage_scheme), that will later automatically apply them on the fly and modify decompilation output (see [examples](https://github.com/mostobriv/herast/tree/main/examples/passives))
OR   
- Match schemes yourself with the help of [Matcher](https://github.com/mostobriv/herast/blob/main/herast/tree/matcher.py) (see [examples](https://github.com/mostobriv/herast/tree/main/examples/scripts))