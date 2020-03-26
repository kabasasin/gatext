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


# /TAG/
# ^
def is_tag_start(s: str) -> (bool, str):
    if s in TAG_START_SYMBOL:
        return True, ""
    elif len(s) > len(sorted(TAG_START_SYMBOL, key=len)[-1]):
        return False, "OVER_MAX_LENGTH"
    else:
        return False, "NOT_MATCH"


# /TAG/
#     ^
def is_tag_end(s: str):
    if s in TAG_END_SYMBOL:
        return True, ""
    elif len(s) > len(sorted(TAG_END_SYMBOL, key=len)[-1]):
        return False, "OVER_MAX_LENGTH"
    else:
        return False, "NOT_MATCH"


# /TAG/ {
#       ^
def is_nested_start(s: str):
    if len(s) > len(sorted(NESTED_SYMBOL, key=lambda x: len(x[0]))[-1]):
        return False, "OVER_MAX_LENGTH"
    for sym in NESTED_SYMBOL:
        if s == sym[0]:
            return True, ""
    return False, "NOT_MATCH"


# /TAG/ { <content> }
#                   ^
def is_nested_end(s: str):
    if len(s) > len(sorted(NESTED_SYMBOL, key=lambda x: len(x[1]))[-1]):
        return False, "OVER_MAX_LENGTH"
    for sym in NESTED_SYMBOL:
        if s == sym[1]:
            return True, ""
    return False, "NOT_MATCH"
