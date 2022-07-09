# Writing patterns
Patterns describe parts of ASTs. To get a better view what AST looks like we recommend using [HRDevHelper](https://github.com/patois/HRDevHelper/).
Herast's patterns are divided into following groups:
- [expressions](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py)
- [instructions](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py)
- [abstracts](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py)
- [helpers](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/helpers.py)

There is also a base pattern for all of them: [BasePat](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/base_pattern.py). It has useful options like skip_casts for ignoring type castings and debug for troubleshooting patterns.


# If example
<p align='center'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/if_example.png'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/if_ast_example.png'>
</p>  
  
Pattern for this AST code will look like this:
```
IfPat(
	ObjPat("debug_on"),
	CallInsnPat(
		ObjPat("printf"),
		AnyPat(),
		StrPat(),
		AnyPat(),
	)
)
```
Notice how there is no need for BlockPat around CallPat, since it is only 1 instruction. Also notice CallInsnPat instead of ExprInsPat(CallPat(...)).

# Struct field access example
<p align='center'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/struct_field_access_example.png'>
<img src='https://github.com/mostobriv/herast/blob/main/pictures/struct_field_access_ast_example.png'>
</p>  
  
Pattern for this AST code will look like this:
```
AsgPat(
	StructFieldAccessPat("struct_1", 0x60),
	CallPat(ObjPat("calloc"), AnyPat(), AnyPat()),
)
```
Notice lack of type casting, since skip_casts is turned on by default in base pattern.

# Patterns table
TODO
