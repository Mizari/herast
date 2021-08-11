import idaapi

idaapi.require('tree.patterns.abstracts')
idaapi.require('tree.patterns.expressions')
idaapi.require('tree.patterns.instructions')
idaapi.require('tree.utils')

from tree.patterns.abstracts import *
from tree.patterns.expressions import CallExprPat, AsgExprPat, ObjPat
from tree.patterns.instructions import ExInsPat, IfInsPat

from tree.utils import *

pattern  =  IfInsPat(
                AnyPat(),
                AsgExprPat(
                    AnyPat(),
                    SkipCasts(CallExprPat(
                            ObjPat(name='__cxa_allocate_exception')
                        )
                    )
                )
            )