import idaapi
import herast.storage_manager as storage_manager

def get_storages():
	return [s for s in storage_manager.schemes_storages.values()]

def get_storage(storage_path):
	return storage_manager.get_storage(storage_path)

def get_func_start(addr):
	func = idaapi.get_func(addr)
	if func is None:
		return idaapi.BADADDR
	return func.start_ea

def get_cfunc(func_ea):
	try:
		cfunc = idaapi.decompile(func_ea)
	except:
		print("Error: failed to decompile function {x}".format(hex(func_ea)))
		return None

	if cfunc is None:
		print("Error: failed to decompile function {x}".format(hex(func_ea)))
	return cfunc