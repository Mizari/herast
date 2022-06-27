import herapi

test_pattern = herapi.ExInsPat(herapi.CallExprPat('_objc_release', ignore_arguments=True))

__exported = [
		herapi.ItemRemovalScheme("remove_objc_release", test_pattern)
]