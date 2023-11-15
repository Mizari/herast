import idautils
import idc
from herapi import *


def is_trampoline_function(func_ea):
	# count blocks
	blocks = [b for b in idautils.Chunks(func_ea)]
	if len(blocks) > 1:
		return False
	block = blocks[0]

	# count instructions
	instrs = [h for h in idautils.Heads(block[0], block[1])]
	disasms = [idc.GetDisasm(i) for i in instrs]

	if len(instrs) == 1:
		return disasms[0].startswith("jmp")

	else:
		return False

trampoline_funcs = [f for f in idautils.Functions() if is_trampoline_function(f)]
trampoline_pattern = ObjPat(*trampoline_funcs, skip_casts=False)

class TrampolineFixScheme(Scheme):
	def __init__(self):
		super().__init__(trampoline_pattern)
	def on_matched_item(self, item, ctx: ASTContext) -> bool:
		def get_trampoline_address(func_ea):
			dis_name = idc.GetDisasm(func_ea)[3:].replace(" ", "")
			if dis_name.startswith("ds:"): dis_name = dis_name[3:]
			if (x := dis_name.find(';')) != -1:
				dis_name = dis_name[:x]
			return idc.get_name_ea_simple(dis_name)
		if (jump_target := get_trampoline_address(item.obj_ea)) == idaapi.BADADDR:
			return False

		new_obj = make_obj(jump_target)
		new_obj.ea = item.ea
		new_obj.type = item.type
		item.replace_by(new_obj)
		return True

register_storage_scheme("trampoline fixer", TrampolineFixScheme())