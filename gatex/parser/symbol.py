TAG_START_SYMBOL = ["\\"]
TAG_END_SYMBOL = ["\\"]

NESTED_SYMBOL = [("{", "}")]

TAG_NAME = ["TITTLE"]


def isNestedSymbolStarter(s: str) -> bool:
    for nested_symbol_pair in NESTED_SYMBOL:
        if nested_symbol_pair[0] == s:
            return True
    return False


def isOverLengthThanNestedSymbolStart(s: str) -> bool:
    if len(s) > len(sorted(NESTED_SYMBOL, key=lambda x: len(x[0]))[-1]):
        return True
    return False
