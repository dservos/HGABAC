from enum import IntEnum, unique


@unique
class ErrorType(IntEnum):
    CRIT = 4
    ERROR = 3
    WARN = 2
    INFO = 1
    NONE = 0


class HGPLError(Exception):
    def __init__(self, message, policy_text=None, pos=-1, etype=ErrorType.ERROR):
        self.default_near_length = 10
        self.policy_text = policy_text
        self.pos = pos
        self.message = message
        self.type = etype
        super().__init__(message)

    def near(self, near_length=10):
        if self.policy_text and self.pos >= 0:
            near_start = self.pos - near_length if self.pos - near_length >= 0 else 0
            near_end = self.pos + near_length + 1 if self.pos + near_length + 1 <= len(self.policy_text) \
                else len(self.policy_text)
            return self.policy_text[near_start:near_end]
        else:
            return None

    def __str__(self):
        string = super().__str__()
        if self.pos >= 0:
            string += " @ char %d" % self.pos
            if self.policy_text:
                string += " near '{}'".format(self.near(self.default_near_length))
        return string


class LexerError(HGPLError):
    def __init__(self, message, policy_text=None, pos=-1, token=None):
        self.token = token
        super().__init__(message, policy_text, pos, ErrorType.ERROR)


class ParserError(HGPLError):
    def __init__(self, message, policy_text=None, pos=-1, token=None, rule=None):
        self.token = token
        self.rule = rule
        super().__init__(message, policy_text, pos, ErrorType.ERROR)

    def __str__(self):
        string = super().__str__()
        if self.rule:
            return string + " while parsing {} rule.".format(self.rule.upper())
        else:
            return string


class TypeCheckerError(HGPLError):
    def __init__(self, message, policy_text=None, pos=-1, token=None, left_token=None, right_token=None, check=None,
                 etype=ErrorType.ERROR):
        self.token = token
        self.check = check
        self.left = left_token
        self.right = right_token
        super().__init__(message, policy_text, pos, etype)


class TypeCheckerWarning(TypeCheckerError):
    def __init__(self, message, policy_text=None, pos=-1, token=None, left_token=None, right_token=None, check=None):
        super().__init__(message, policy_text, pos, token, left_token, right_token, check, ErrorType.WARN)


class InterpreterError(HGPLError):
    def __init__(self, message, policy_text=None, pos=-1, node=None, left=None, right=None, rule=None,
                 etype=ErrorType.ERROR):
        self.node = node
        self.rule = rule
        self.left = left
        self.right = right
        super().__init__(message, policy_text, pos, etype)


class InterpreterWarning(InterpreterError):
    def __init__(self, message, policy_text=None, pos=-1, node=None, left=None, right=None, rule=None):
        super().__init__(message, policy_text, pos, node, left, right, rule, ErrorType.WARN)