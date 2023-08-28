import idautils
import idc
import re
from herapi import *


def is_nullsub_function(func_ea):
	# count blocks
	blocks = [b for b in idautils.Chunks(func_ea)]
	if len(blocks) > 1:
		return False
	block = blocks[0]

	# count instructions
	instrs = [h for h in idautils.Heads(block[0], block[1])]
	disasms = [idc.GetDisasm(i) for i in instrs]

	if len(instrs) == 2:
		# first is xor rax|eax
		d0 = disasms[0]
		p1 = re.compile("xor[ ]*(eax|rax), (eax|rax).*")  # mov rax, 0
		p2 = re.compile("mov[ ]*(eax|rax), \d+.*")        # mov rax, !0
		if re.fullmatch(p1, d0) is None and re.fullmatch(p2, d0) is None:
			return False

		# second is retn
		d1 = disasms[1]
		if not d1.startswith("retn"):
			return False

	elif len(instrs) == 1:
		return disasms[0].startswith("retn")

	else:
		return False


class NullsubRemovalScheme(Scheme):
	def __init__(self):
		nullsub_funcs = [f for f in idautils.Functions() if is_nullsub_function(f)]
		# some useful logic might be in names
		nullsub_funcs = [f for f in nullsub_funcs if idaapi.get_name(f).startswith("sub_")]
		pattern = ObjPat(*nullsub_funcs)
		pattern = CallInsnPat(pattern)
		super().__init__(pattern)

	def on_matched_item(self, item, ctx: PatternContext) -> bool:
		ctx.modify_instr(item, None)
		return False


register_storage_scheme("nullsub remover", NullsubRemovalScheme())