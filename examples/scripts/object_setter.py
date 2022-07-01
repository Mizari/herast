import idaapi
import herapi
import idc


class ObjectSetterScheme(herapi.SPScheme):
	def __init__(self, function_address):
		self.objects = {}
		call_pattern = herapi.SkipCasts(herapi.CallPat(function_address, herapi.NumPat(), herapi.NumPat(), herapi.AnyPat()))
		pattern = herapi.AsgPat(herapi.ObjPat(), call_pattern)
		super().__init__("object_setter", pattern)

	def on_matched_item(self, item, ctx: herapi.PatternContext):
		asg_y = herapi.strip_casts(item.y)
		arg0 = asg_y.a[0].n._value
		arg1 = asg_y.a[1].n._value
		object_name = "object_" + hex(arg0)[2:] + '_' + str(arg1)
		object_address = item.x.obj_ea
		object_type    = None
		self.add_object(object_address, object_name, object_type)
		return False

	def add_object(self, object_ea, object_name, object_type):
		if self.objects.get(object_ea) is None:
			self.objects[object_ea] = (object_name, object_type)
			return

		existing_object_name, existing_object_type = self.objects[object_ea]
		if object_name is None:
			object_name = existing_object_name
		if object_type is None:
			object_type = existing_object_type

		if existing_object_name != object_name:
			print(f"Warning: object address {object_ea} is already used by object {existing_object_name}")
		if existing_object_type != object_type:
			print(f"Warning: object address {object_ea} is already used by object {existing_object_type}")

		self.objects[object_ea] = (object_name, object_type)

	def apply_new_info(self, default_type=None):
		print("Found {} objects".format(len(self.objects)))
		for oaddr, (oname, otype) in self.objects:
			print("Setting object: {:x} {} {}".format(oaddr, oname, otype))
			if oname is not None:
				idaapi.set_name(oaddr, oname)

			if otype is not None:
				idc.SetType(oaddr, otype)
			elif default_type is not None:
				idc.SetType(oaddr, default_type)


def collect_objects(function_address, default_type=None):
	if function_address == idaapi.BADADDR:
		print("Error: function address is invalid")
		return

	scheme = ObjectSetterScheme(function_address)
	matcher = herapi.Matcher()
	matcher.add_scheme(scheme)
	matcher.match_objects_xrefs(function_address)
	scheme.apply_new_info(default_type)