# call_explore
TODO

# collapse_exception_branch
Replaces long and complex exception throwing instruction into short and simple __throw_if function call

# flareon_7_chal
TODO

# propagate_error
Replaces
```
if (error_var) {
	logic_expr;
} else {
	error_var = logic_expr;
}
```
into
```
error_var = __propagate_error(error_var, logic_expr);
```

# sharedptr
Removes or replaces with simple function call some shared pointer logic of C++

# wasm_str_lit_cref_definer
TODO