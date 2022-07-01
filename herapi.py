# forward imports for herast usage
from herast.tree.patterns.abstracts import *
from herast.tree.patterns.expressions import *
from herast.tree.patterns.instructions import *
from herast.tree.patterns.helpers import *
from herast.settings.settings_manager import *
from herast.passive_manager import *

from herast.tree.utils import make_call_helper_instr, strip_casts
from herast.tree.matcher import Matcher
from herast.schemes.single_pattern_schemes import SPScheme, ItemRemovalScheme