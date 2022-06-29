import herapi

test_pattern = herapi.ExInsPat(herapi.CallExprPat('_objc_release', ignore_arguments=True))

herapi.add_storage_scheme(herapi.ItemRemovalScheme("remove_objc_release", test_pattern))