from enum import Enum, unique

from hgpl.errors import LexerError


@unique
class TokenType(Enum):
    # TODO: Make this an IntEnum like ASTNodeType?
    OP = 1
    BOOL_OP = 2
    NOT_OP = 3
    USR_ATT = 4
    OBJ_ATT = 5
    ENV_ATT = 6
    ADM_ATT = 7
    CON_ATT = 8
    UNK_ATT = 9
    UNK_ID = 10
    NULL = 11
    BOOL = 12
    INT = 13
    FLOAT = 14
    STRING = 15
    LSET = 16
    RSET = 17
    LPARN = 18
    RPARN = 19
    COMMA = 20
    START = 21
    END = 22


class Token(object):
    def __init__(self, ttype, pos=-1, value=None):
        self.type = ttype
        self.value = value
        self.pos = pos

    def __str__(self):
        if self.value and str(self.value):
            if self.type == TokenType.STRING:
                return "Token({}, {})".format(self.type.name, repr(self.value))
            else:
                return "Token({}, {})".format(self.type.name, self.value)
        else:
            return "Token({})".format(self.type.name)

    def __repr__(self):
        if self.value and repr(self.value):
            if self.pos >= 0:
                return "Token({}, {}, {})".format(str(self.type), self.pos, repr(self.value))
            else:
                return "Token({}, value={})".format(str(self.type), repr(self.value))
        else:
            if self.pos >= 0:
                return "Token({}, {})".format(str(self.type), self.pos)
            else:
                return "Token({})".format(str(self.type))

    def __eq__(self, other):
        if isinstance(other, Token) and self.type == other.type and self.value == other.value and self.pos == other.pos:
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class Lexer(object):
    def __init__(self, policy_text):
        self._policy_text = policy_text
        self._text_pos = 0
        if len(policy_text) > 0:
            self._current_char = self._policy_text[self._text_pos]
        else:
            self._current_char = None
        self._token_list = [Token(TokenType.START, self._text_pos)]
        self._att_list = []

    def _peek(self, i=1):
        if self._text_pos + i > len(self._policy_text) - 1:
            return None
        else:
            return self._policy_text[self._text_pos + i]

    def _advance(self):
        self._text_pos += 1
        if self._text_pos > len(self._policy_text) - 1:
            self._current_char = None
        else:
            self._current_char = self._policy_text[self._text_pos]

    def _whitespace(self):
        while self._current_char and self._current_char.isspace():
            self._advance()

    def _string_char(self):
        if 35 <= ord(self._current_char) <= 126:
            return True
        elif ord(self._current_char) == 32 or ord(self._current_char) == 33:
            return True
        else:
            return False

    def _number(self):
        ttype = TokenType.INT
        numstring = self._current_char
        pos_at_start = self._text_pos
        while self._peek() and (self._peek().isdigit() or self._peek() == "."):
            if self._peek().isdigit():
                self._advance()
                numstring += self._current_char
            elif self._peek() == "." and ttype == TokenType.INT:
                self._advance()
                if self._peek() and self._peek().isdigit():
                    ttype = TokenType.FLOAT
                    numstring += self._current_char
                else:
                    raise LexerError(
                        "Syntax error encountered while reading floating point number. '.' should be followed by a "
                        "digit and not '{}'.".format(self._peek()), self._policy_text, self._text_pos + 1,
                        Token(TokenType.FLOAT, pos_at_start))
            else:
                raise LexerError("Syntax error encountered while reading floating point number. Found multiple '.'s in "
                                 "number.", self._policy_text, self._text_pos + 1, Token(TokenType.FLOAT, pos_at_start))

        if ttype == TokenType.INT:
            return Token(ttype, pos_at_start, int(numstring))
        else:
            return Token(ttype, pos_at_start, float(numstring))

    def _string(self):
        # TODO: Update to V2
        string = ""
        pos_at_start = self._text_pos
        self._advance()
        while self._current_char != "\"":
            if not self._current_char:
                raise LexerError("Syntax error encountered while reading string. End of policy encountered before"
                                 " matching \".", self._policy_text, pos_at_start,
                                 Token(TokenType.STRING, pos_at_start))
            elif self._string_char():
                string += self._current_char
            else:
                raise LexerError("Syntax error encountered while reading string. Invalid character, "
                                 "'{}', found in string.".format(self._current_char), self._policy_text, self._text_pos,
                                 Token(TokenType.STRING, pos_at_start))
            self._advance()
        return Token(TokenType.STRING, pos_at_start, string)

    def _id(self):
        ident = self._current_char
        while self._peek() and (self._peek().isalpha() or self._peek().isdigit() or self._peek() == "_"):
            self._advance()
            ident += self._current_char
        return ident

    def policy(self):
        return self._policy_text

    def toke_list(self):
        return self._token_list[:]

    def att_list(self):
        # TODO: Make it so att_list does not have duplicates.
        return self._att_list[:]

    def current(self):
        return self._token_list[-1]

    def token_string(self):
        tstring = ""
        for t in self._token_list:
            tstring += t.type.name + " "
        return tstring[:-1]

    def tokenize(self):
        while self.next():
            pass

    def next(self):
        next_token = None

        self._whitespace()
        if not self._current_char:
            if self._token_list[-1].type != TokenType.END:
                next_token = Token(TokenType.END, self._text_pos)
            else:
                return None
        elif self._current_char == "{":
            next_token = Token(TokenType.LSET, self._text_pos)
        elif self._current_char == "}":
            next_token = Token(TokenType.RSET, self._text_pos)
        elif self._current_char == ",":
            next_token = Token(TokenType.COMMA, self._text_pos)
        elif self._current_char == "(":
            next_token = Token(TokenType.LPARN, self._text_pos)
        elif self._current_char == ")":
            next_token = Token(TokenType.RPARN, self._text_pos)
        elif self._current_char == "=":
            next_token = Token(TokenType.OP, self._text_pos, "=")
        elif self._current_char == ">":
            if self._peek() == "=":
                next_token = Token(TokenType.OP, self._text_pos, ">=")
                self._advance()
            else:
                next_token = Token(TokenType.OP, self._text_pos, ">")
        elif self._current_char == "<":
            if self._peek() == "=":
                next_token = Token(TokenType.OP, self._text_pos, "<=")
                self._advance()
            else:
                next_token = Token(TokenType.OP, self._text_pos, "<")
        elif self._current_char == "!":
            if self._peek() == "=":
                next_token = Token(TokenType.OP, self._text_pos, "!=")
                self._advance()
            else:
                raise LexerError("Syntax error, found '!' without matching '='. Found "
                                 "'{}' in place of '='.".format(self._current_char), self._policy_text,
                                 self._text_pos + 1, Token(TokenType.OP, self._text_pos, "!="))
        elif self._current_char == "\"":
            next_token = self._string()
        elif self._current_char.isdigit() or (self._current_char == "-" and self._peek() and self._peek().isdigit()):
            next_token = self._number()
        elif self._current_char.isalpha():
            pos_at_start = self._text_pos
            prefix = self._id()
            if self._peek() == ".":
                self._advance()
                self._advance()
                if self._current_char.isalpha() or self._current_char.isdigit() or self._current_char == "_":
                    ident = self._id()
                    if prefix.lower() == "user":
                        token_type = TokenType.USR_ATT
                    elif prefix.lower() == "object":
                        token_type = TokenType.OBJ_ATT
                    elif prefix.lower() == "env":
                        token_type = TokenType.ENV_ATT
                    elif prefix.lower() == "admin":
                        token_type = TokenType.ADM_ATT
                    elif prefix.lower() == "connect":
                        token_type = TokenType.CON_ATT
                    else:
                        raise LexerError("Syntax error encountered while reading attribute name. '{}' is not a valid "
                                         "attribute type.".format(prefix), self._policy_text,
                                         pos_at_start, Token(TokenType.UNK_ATT, pos_at_start, prefix.lower()))
                    next_token = Token(token_type, pos_at_start, ident)
                    self._att_list.append(next_token)
                else:
                    raise LexerError("Syntax error encountered while reading attribute name. '.' needs to be followed "
                                     "by an identifier and not '{}'.".format(self._current_char), self._policy_text,
                                     self._text_pos, Token(TokenType.UNK_ATT, pos_at_start, prefix.lower()))
            elif prefix.lower() in ("in", "subset"):
                next_token = Token(TokenType.OP, pos_at_start, prefix.upper())
            elif prefix.lower() in ("and", "or"):
                next_token = Token(TokenType.BOOL_OP, pos_at_start, prefix.upper())
            elif prefix.lower() in ("true", "false", "undef"):
                next_token = Token(TokenType.BOOL, pos_at_start, prefix.upper())
            elif prefix.lower() == "not":
                next_token = Token(TokenType.NOT_OP, pos_at_start, "NOT")
            elif prefix.lower() == "null":
                next_token = Token(TokenType.NULL, pos_at_start, "NULL")
            else:
                raise LexerError("Syntax error, encountered an unknown identifier, '{}'.".format(prefix),
                                 self._policy_text, pos_at_start, Token(TokenType.UNK_ID, pos_at_start, prefix))
        if next_token:
            self._token_list.append(next_token)
            self._advance()
        else:
            raise LexerError("Syntax error, encountered an unexpected character, '{}'.".format(self._current_char),
                             self._policy_text, self._text_pos)

        return next_token
