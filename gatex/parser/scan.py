from typing import Callable, List

from gatex.parser.stack import CONTENT_STACK, TAG_STACK, NO_STEP_REG
# from gatex.parser.symbol import is_tag_start, is_tag_end
# from gatex.parser.symbol import TAG_START_SYMBOL, TAG_NAME, TAG_END_SYMBOL
from gatex.parser.symbol import *


class Scanner(object):
    def __init__(self):
        self.file = None

    def load_file(self, file_name):
        self.file = open(file_name)

    def eat(self):
        # finite set of input symbols Σ
        if NO_STEP_REG.get():
            NO_STEP_REG.set(False)
            return
        c = self.file.read(1)
        if not c:
            CONTENT_STACK.push(chr(0))
        else:
            CONTENT_STACK.push(c)

    def match(self):
        dfa = Parse(StartState(), self.eat)
        dfa.run()
        for state in dfa.transit_list:
            print(state)


class State(object):
    # finite set of `states` (Q)
    name = "EMPTY"

    def __init__(self):
        self.content = ""

    def transit(self) -> object:
        # transition `function` δ: Q x Σ -> Q
        return self

    def __repr__(self):
        return "{}: {}".format(self.name, self.content)


class StopState(State):
    name = "STOP"

    def transit(self):
        if CONTENT_STACK.content != "":
            raise Exception("parser failed: {}".format(CONTENT_STACK.content))
        # return None


class StartState(State):
    # initial or start state q0
    name = "Start"

    def transit(self) -> State:
        return Content()


class Content(State):
    name = "Content"
    tag = True
    mark = True
    # possible = False

    def transit(self) -> State:
        if CONTENT_STACK.content == chr(0):
            return StopState()
        # TAG or Mark
        if self.tag:
            res, reason = is_tag_start(CONTENT_STACK.content)
            # match tag start symbol
            if res:
                NO_STEP_REG.set(True)
                return TagStart()
            else:
                # too lang for tag start
                if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                    self.tag = False
                # not match this time: try mark or eat more rune
                elif reason == POSSIBLE:
                    self.tag = True
                else:
                    return StopState()
        if self.mark:
            res, reason = is_mark(CONTENT_STACK.content)
            if res:
                NO_STEP_REG.set(True)
                # match tag start symbol
                return Mark()
            else:
                # too lang for MARK
                if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                    self.mark = False
                # not match this time: eat more rune
                elif reason == POSSIBLE:
                    self.mark = True
                else:
                    return StopState()
        # not tag or mark
        # other contents
        self.content += CONTENT_STACK.pop_all()
        self.tag = True
        self.mark = True
        return self


class Mark(State):
    name = "Mark"

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        return Content()


class TagStart(State):
    name = "TagStart"

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        TAG_STACK.append(self.content)
        return TagReadName()


class TagReadName(State):
    name = "Tag"

    def transit(self) -> State:
        res, reason = is_tag_name(CONTENT_STACK.content)
        if res:
            self.content = CONTENT_STACK.pop_all()
            return TagEnd()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                return StopState()
            elif reason == POSSIBLE:
                return self
            else:
                return StopState()


class TagEnd(State):
    name = "TagEnd"

    def transit(self) -> State:
        res, reason = is_tag_end(CONTENT_STACK.content)
        if res:
            if TAG_STACK[-1] != CONTENT_STACK.content:
                return StopState()
            else:
                self.content = CONTENT_STACK.pop_all()
                TAG_STACK.pop(-1)
                return Content()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                return StopState()
            elif reason == POSSIBLE:
                return self
            else:
                return StopState()


# class BlockStart(State):
#     name = "NestedTagStart"
#
#     def transit(self) -> State:
#         res, reason = is_block_start(CONTENT_STACK.content)
#         if res:
#             self.content = CONTENT_STACK.pop_all()
#             TAG_STACK.append(self.content)
#             return NestedTagReadName()
#         else:
#             if
#                 return StopState()
#             return self
#
#
#
# class NestedTagEnd(State):
#     pass


class Parse(object):
    # DFA
    def __init__(self, state: State, eat: Callable):
        # initial `state` q0
        self.init = state
        self.current = self.init
        self.eat_function = eat

        self.transit_list: List[State] = []
        self.transit_list.append(self.init)

    def run(self):
        while True:
            self.current = self.current.transit()
            if self.current.name == "STOP":
                self.save()
                return
            self.save()
            self.eat_function()

    def save(self):
        # TODO BUILD AST
        if self.transit_list[-1].name != self.current.name:
            self.transit_list.append(self.current)
