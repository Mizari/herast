from herast.tree.patterns.expressions import CallExprPat
from herast.tree.patterns.instructions import ExInsPat

from herast.schemes.single_pattern_schemes import ItemRemovalScheme


test_pattern = ExInsPat(CallExprPat('_objc_release', ignore_arguments=True))

__exported = [
		ItemRemovalScheme("remove_objc_release", test_pattern)
]