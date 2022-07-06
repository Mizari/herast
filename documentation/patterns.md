# Writing patterns
Patterns describe parts of ASTs. To get a better view what AST looks like we recommend using [HRDevHelper](https://github.com/patois/HRDevHelper/).
Herast's patterns are divided into following groups:
- [expressions](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/expressions.py)
- [instructions](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/instructions.py)
- [abstracts](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/abstracts.py)
- [helpers](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/helpers.py)

There is also a base pattern for all of them: [BasePattern](https://github.com/mostobriv/herast/blob/main/herast/tree/patterns/base_pattern.py). It has useful options like skip_casts for ignoring type castings and debug for troubleshooting patterns.


# Patterns table
TODO