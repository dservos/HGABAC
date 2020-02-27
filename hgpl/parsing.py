from hgpl.lexing import Lexer, TokenType
from hgpl.ast import *
from hgpl.errors import ParserError


class Parser(object):
    def __init__(self, lexer, policy=None):
        if isinstance(lexer, Lexer):
            lexer.tokenize()
            self._lexer = lexer
            self._token_list = lexer.toke_list()
            self._policy = self._lexer.policy()
        elif isinstance(lexer, list):
            self._token_list = lexer[:]
            self._lexer = None
            self._policy = policy
        else:
            # TODO: Make user defined exception for this
            raise Exception()
        self._pos = 0
        self._current_token = self._token_list[self._pos]

    def policy(self):
        return self._policy

    def _peek(self, i=1):
        if self._pos + i > len(self._token_list):
            return None
        return self._token_list[self._pos + i]

    def _advance(self):
        self._pos += 1
        if self._pos >= len(self._token_list):
            self._current_token = None
        else:
            self._current_token = self._token_list[self._pos]

    def _eat(self, token_type, rule=None, msg=None):
        if self._current_token.type == token_type:
            result = self._current_token
            self._advance()
        else:
            if msg is None:
                msg = "Parse Error, expected {} token but encountered {}.".format(token_type.name,
                                                                                  self._current_token.type.name)
            raise ParserError(msg, self._policy, self._current_token.pos, self._current_token, rule)
        return result

    @staticmethod
    def _is_const(token):
        return Parser._is_atomic(token) or token.type == TokenType.LSET

    @staticmethod
    def _is_att(token):
        return token.type in (TokenType.USR_ATT, TokenType.OBJ_ATT, TokenType.ADM_ATT, TokenType.ENV_ATT,
                              TokenType.CON_ATT)

    @staticmethod
    def _is_atomic(token):
        return token.type in (TokenType.INT, TokenType.FLOAT, TokenType.STRING, TokenType.NULL)

    def _att_name_rule(self):
        if self._current_token.type == TokenType.USR_ATT:
            node = UsrAttNode(self._eat(TokenType.USR_ATT, "att_name"))
        elif self._current_token.type == TokenType.OBJ_ATT:
            node = ObjAttNode(self._eat(TokenType.OBJ_ATT, "att_name"))
        elif self._current_token.type == TokenType.ADM_ATT:
            node = AdmAttNode(self._eat(TokenType.ADM_ATT, "att_name"))
        elif self._current_token.type == TokenType.ENV_ATT:
            node = EnvAttNode(self._eat(TokenType.ENV_ATT, "att_name"))
        else:
            node = ConAttNode(self._eat(TokenType.CON_ATT, "att_name", "Syntax error, expected attribute name and not "
                                                                       "{}.".format(self._current_token.type.name)))
        return node

    def _bool_var_rule(self):
        if self._current_token.type == TokenType.BOOL:
            node = BoolValNode(self._eat(TokenType.BOOL, "bool_var"))
        else:
            node = self._att_name_rule()
        return node

    def _atomic_rule(self):
        # TODO: Update to V2
        if self._current_token.type == TokenType.INT:
            node = IntValNode(self._eat(TokenType.INT, "atomic"))
        elif self._current_token.type == TokenType.FLOAT:
            node = FloatValNode(self._eat(TokenType.FLOAT, "atomic"))
        elif self._current_token.type == TokenType.STRING:
            node = StringValNode(self._eat(TokenType.STRING, "atomic"))
        else:
            node = NullValNode(self._eat(TokenType.NULL, "atomic", "Syntax error, expected atomic constant and not {}."
                                         .format(self._current_token.type.name)))
        return node

    def _set_rule(self):
        nodes = []
        set_start_token = self._eat(TokenType.LSET, "set", "Syntax error, expected '{{' not {} in set notation."
                                    .format(self._current_token.type.name))

        if self._current_token.type != TokenType.RSET:
            nodes.append(self._atomic_rule())
            while self._current_token.type != TokenType.RSET:
                self._eat(TokenType.COMMA, "set", "Syntax error, expected ',' not {} in set notation."
                          .format(self._current_token.type.name))
                nodes.append(self._atomic_rule())

        set_end_token = self._eat(TokenType.RSET, "set", "Syntax error, expected '}}' not {} in set notation."
                                  .format(self._current_token.type.name))
        return SetNode(set_start_token, set_end_token, nodes)

    def _const_rule(self):
        if Parser._is_atomic(self._current_token):
            node = self._atomic_rule()
        else:
            node = self._set_rule()
        return node

    def _var_rule(self):
        if Parser._is_att(self._current_token):
            node = self._att_name_rule()
        elif Parser._is_const(self._current_token):
            node = self._const_rule()
        else:
            raise ParserError("Syntax error, unexpected {} at char {}. Expected attribute or constant."
                              .format(self._current_token.type.name, self._current_token.pos), self._policy,
                              self._current_token.pos, self._current_token, "var")
        return node

    def _exp_rule(self):
        if self._current_token.type == TokenType.NOT_OP:
            not_op_token = self._eat(TokenType.NOT_OP, "exp")
            if self._current_token.type == TokenType.LPARN:
                token = self._eat(TokenType.LPARN, "exp")
                subnode = self._policy_rule()
                self._eat(TokenType.RPARN, "exp", "Syntax error, '(' at char {} is missing matching ')'."
                          .format(token.pos))
            else:
                subnode = self._bool_var_rule()
            node = NotNode(not_op_token, subnode)
        elif self._current_token.type == TokenType.LPARN:
            token = self._eat(TokenType.LPARN, "exp")
            node = self._policy_rule()
            self._eat(TokenType.RPARN, "exp", "Syntax error, '(' at char {} is missing matching ')'."
                      .format(token.pos))
        elif self._current_token.type == TokenType.LSET or (self._peek() and self._peek().type == TokenType.OP and
                                                            (Parser._is_att(self._current_token) or Parser._is_const(
                                                                    self._current_token))):
            left = self._var_rule()
            op_token = self._eat(TokenType.OP, "exp", "Syntax error, expected operation not {}."
                                 .format(self._current_token.type.name))
            right = self._var_rule()
            node = OpNode(op_token, left, right)
        elif self._current_token.type == TokenType.BOOL or Parser._is_att(self._current_token):
            node = self._bool_var_rule()
        else:
            raise ParserError("Syntax error, unexpected {} at char {}. Expected start of EXP rule."
                              .format(self._current_token.type.name, self._current_token.pos), self._policy,
                              self._current_token.pos, self._current_token, "exp")
        return node

    def _term_rule(self):
        node = self._exp_rule()

        while self._current_token.type == TokenType.BOOL_OP and self._current_token.value == "AND":
            node = BoolOpNode(self._eat(TokenType.BOOL_OP, "term"), node, self._exp_rule())

        return node

    def _policy_rule(self):
        # Based on ( policy ) rule from original grammar. Removed as it was an error:
        # if self._current_token.type == TokenType.LPARN:
        #    token = self._eat(TokenType.LPARN, "policy")
        #    node = self._policy_rule()
        #    self._eat(TokenType.RPARN, "policy", "Syntax error, '(' at char {} is missing matching ')'."
        #              .format(token.pos))
        # else:

        # Based on V1 grammar where everything was just right right-associativity:
        # node = self._exp_rule()
        # if self._current_token.type == TokenType.BOOL_OP:
        #    bool_op_token = self._eat(TokenType.BOOL_OP, "policy")
        #    right = self._policy_rule()
        #    node = BoolOpNode(bool_op_token, node, right)
        # return node

        node = self._term_rule()

        while self._current_token.type == TokenType.BOOL_OP and self._current_token.value == "OR":
            node = BoolOpNode(self._eat(TokenType.BOOL_OP, "policy"), node, self._term_rule())

        return node

    def parse(self):
        # TODO: Reset if called 2nd time.
        self._eat(TokenType.START, "parse", "Syntax error, missing START token at beginning of token list.")
        result = self._policy_rule()
        self._eat(TokenType.END, "parse", "Syntax error, expected END token marking end of policy.")
        return result
