from herapi import *

test_pattern = ExprInsPat(CallPat('_objc_release', ignore_arguments=True))

register_storage_scheme(ItemRemovalScheme("remove_objc_release", test_pattern))