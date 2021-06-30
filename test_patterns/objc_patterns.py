import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, HelperExprPat

obj_release_pattern = CallExprPat(ObjPat('_objc_release'))