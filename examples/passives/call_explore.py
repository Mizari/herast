import herapi

test_pattern = herapi.ExprInsPat(herapi.CallPat('_objc_release', ignore_arguments=True))

herapi.register_storage_scheme(herapi.ItemRemovalScheme("remove_objc_release", test_pattern))