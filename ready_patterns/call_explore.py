from tree.patterns.expressions import CallExprPat
from tree.patterns.instructions import ExInsPat

from schemes.single_pattern_schemes import ItemRemovalScheme


test_pattern = ExInsPat(CallExprPat('_objc_release', ignore_arguments=True))

__exported = [
		ItemRemovalScheme("remove_objc_release", test_pattern)
]