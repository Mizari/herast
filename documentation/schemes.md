# Writing schemes
Schemes require unique name and one or multiple patterns. Name is used for singling out what schemes are useful and what arent (herapi.enable_scheme, herapi.disable_scheme), also for finding schemes for their further dynamic updating.
Schemes should overwrite following callbacks (that will be called by Matcher):
- on_matched_item describes what to do with found item, that matches scheme's pattern
- on_tree_iteration_start describes what to do before iteration, typically initialization and state clearing, since matching can start multiple times for a single function in an event of AST modification
- on_tree_iteration_end described what to do with collected information/items during matching
