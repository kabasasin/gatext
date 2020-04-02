class Stack(list):
    name = ''


class ContentStack(object):
    def __init__(self):
        self.content = ""

    def push(self, s):
        self.content += s

    def pop(self) -> str:
        s = self.content[-1]
        self.content = self.content[:-1]
        return s

    def pop_all(self) -> str:
        s = self.content
        self.content = ''
        return s


class BoolReg(object):
    def __init__(self):
        self.value = False

    def set(self, value: bool):
        self.value = value

    def get(self) -> bool:
        return self.value


CONTENT_STACK = ContentStack()
TAG_STACK = Stack()
NO_STEP_REG = BoolReg()
NO_SAVE_REG = BoolReg()
FORCE_SAVE_REG = BoolReg()
SPACE_EAT_REG = BoolReg()
SAVE_REG = BoolReg()
