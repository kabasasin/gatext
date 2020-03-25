from typing import Callable

from gatex.parser.symbol import TAG_START_SYMBOL, TAG_NAME, TAG_END_SYMBOL
from gatex.parser.stack import CONTENT_STACK, TAG_STACK, NO_STEP_REG
from gatex.parser.symbol import isNestedSymbolStarter, isOverLengthThanNestedSymbolStart


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
            print(state.name, ":", state.content)


class State(object):
    # finite set of `states` (Q)
    name = "EMPTY"

    def __init__(self):
        self.content = ""

    def transit(self) -> object:
        # transition `function` δ: Q x Σ -> Q
        return self

    def __repr__(self):
        return "STATE: {}".format(self.name)


class StopState(State):
    name = "STOP"

    def transit(self) -> object:
        if CONTENT_STACK.content != "":
            raise Exception("parser failed: {}".format(CONTENT_STACK.content))
        return None


class StartState(State):
    # initial or start state q0
    name = "Start"

    def transit(self) -> object:
        return TagStart()


class TagStart(State):
    name = "TagStart"

    def transit(self) -> object:
        if CONTENT_STACK.content in TAG_START_SYMBOL:
            self.content = CONTENT_STACK.pop_all()
            TAG_STACK.append(self.content)
            return TagReadName()
        else:
            if len(CONTENT_STACK.content) > len(sorted(TAG_START_SYMBOL, key=len)[-1]):
                return StopState()
            return TagStart()


class TagReadName(State):
    name = "Tag"

    def transit(self) -> object:
        if CONTENT_STACK.content in TAG_NAME:
            self.content = CONTENT_STACK.pop_all()
            return TagEnd()
        else:
            if len(CONTENT_STACK.content) > len(sorted(TAG_NAME, key=len)[-1]):
                return StopState()
            return self


class TagEnd(State):
    name = "TagEnd"

    def transit(self) -> object:
        if CONTENT_STACK.content in TAG_END_SYMBOL:
            if TAG_STACK[-1] != CONTENT_STACK.content:
                return StopState()
            else:
                self.content = CONTENT_STACK.pop_all()
                TAG_STACK.pop(-1)
                return Content()
        else:
            if len(CONTENT_STACK.content) > len(sorted(TAG_START_SYMBOL, key=len)[-1]):
                return StopState()
            return TagStart()


class NestedTagStart(State):
    name = "NestedTagStart"

    def transit(self) -> State:
        if isNestedSymbolStarter(CONTENT_STACK.content):
            self.content = CONTENT_STACK.pop_all()
            TAG_STACK.append(self.content)
            return NestedTagReadName()
        else:
            if isOverLengthThanNestedSymbolStart(CONTENT_STACK.content):
                return StopState()
            return self


class NestedTagReadName(State):
    name = "NestedTagReadName"

    def transit(self) -> State:
        if CONTENT_STACK.content in TAG_NAME:
            # TODO
            pass


class Content(State):
    name = "Content"

    def transit(self) -> State:
        if CONTENT_STACK.content in TAG_START_SYMBOL:
            NO_STEP_REG.set(True)
            return TagStart()
        elif CONTENT_STACK.content == chr(0):
            return StopState()
        else:
            self.content += CONTENT_STACK.pop_all()
            return self


class Parse(object):
    # DFA
    def __init__(self, state: State, eat: Callable):
        # initial `state` q0
        self.init = state
        self.current = self.init
        self.eat_function = eat

        self.transit_list = []

    def run(self):
        while True:
            self.current = self.current.transit()
            if self.current.name == "STOP":
                self.save()
                return
            self.save()
            self.eat_function()

    def save(self):
        # TODO BUILD CONTENT TREE
        if not len(self.transit_list):
            self.transit_list.append(self.current)
        elif self.transit_list[-1].name != self.current.name:
            self.transit_list.append(self.current)
