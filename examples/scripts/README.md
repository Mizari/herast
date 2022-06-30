# assignment_counter
This script show how to count assignments of objects created by function calls to anything. Useful to find some popular functions.

# calls_parser
This example shows how to automate objects renamings from this:  
	import_function("FooFunction", &dword_123456);  
to this  
	import_function("FooFunction", &FooFunction);  

# function_renamer
This script renames functions according to pattern found in them

# object_setter
This example demonstrates how to mass-set objects according to how they are assigned values by function calls.  
e.g.:   
	dword_123456 = Foo(123, 3, "not used")  
into  
	object_7b_3 =  Foo(123, 3, "not used")  

# virtual_collector
This example show how to automate objects collecting of this form:  
	some_struct_pointer->some_field = some_value;