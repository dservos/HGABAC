from enum import Enum

from hgpl.parsing import Parser
from hgpl.ast import *
from hgpl.symbols import *
from hgpl.errors import TypeCheckerError, TypeCheckerWarning, ErrorType



@unique
class TypeCheckerResult(Enum):
    NONE = 1
    PASS = 2
    WARN = 3
    ERROR = 4


class TypeChecker(object):
    # TODO: Deal with chains of attribute comparisons (e.g. user.a = user.b and user.b >= user.c or user.c < 5).
    def __init__(self, parser, policy=None):
        self._symbols = SymbolTable()
        self._issues = []
        self._checked = False

        if isinstance(parser, Parser):
            self._parser = parser
            self._policy = parser.policy()
            self._ast = parser.parse()
        elif isinstance(parser, ASTNode):
            self._ast = parser
            self._parser = None
            self._policy = policy
        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def _att_node(self, node):
        s = Symbol(node.tvalue(), node.ttype(), SymbolType.UNKNOWN)
        self._symbols.define(s)

    def _att_check(self, node):
        left_node = node.left()
        right_node = node.right()

        if not left_node or not right_node:
            # TODO: Make user defined exception for this
            raise Exception()

        if isinstance(left_node, AttNode) and isinstance(right_node, AttNode):
            left_name = Symbol.att_to_symbol_name(left_node)
            right_name = Symbol.att_to_symbol_name(right_node)
            left_symbol = self._symbols.lookup(left_name)
            right_symbol = self._symbols.lookup(right_name)

            if left_symbol and right_symbol:
                if left_symbol.type == SymbolType.UNKNOWN and left_symbol.type != SymbolType.UNKNOWN:
                    self._symbols.switch_type(left_symbol.name, right_symbol.type)
                    left_symbol.type = right_symbol.type
                elif right_symbol.type == SymbolType.UNKNOWN and right_symbol.type != SymbolType.UNKNOWN:
                    self._symbols.switch_type(right_symbol.name, left_symbol.type)
                    right_symbol.type = left_symbol.type
                elif left_symbol.type != right_symbol.type \
                        and not (left_symbol.type in (SymbolType.INT, SymbolType.FLOAT) and right_symbol.type in
                            (SymbolType.INT, SymbolType.FLOAT)):
                    self._type_error(node, "Possible type error with attributes {} and {}. Attributes compared with "
                                           "different types and each other".format(left_symbol.name, right_symbol.name),
                                     "att_check", left_node, right_node)
            else:
                # TODO: Make user defined exception for this
                raise Exception()
        else:
            if isinstance(left_node, AttNode):
                att_node = left_node
                val_node = right_node
            else:
                att_node = right_node
                val_node = left_node

            symbol = self._symbols.lookup(Symbol.att_to_symbol_name(att_node))
            val_type = SymbolType.convert_token_type(val_node.ttype())

            if symbol:
                if symbol.type == SymbolType.UNKNOWN:
                    self._symbols.switch_type(symbol.name, val_type)
                elif symbol.type != val_type and not (symbol.type in (SymbolType.INT, SymbolType.FLOAT) and val_type in
                     (SymbolType.INT, SymbolType.FLOAT)):
                    self._type_error(node, "Possible type error with attribute {}. Attribute compared with different "
                                           "types.".format(symbol.name), "att_check", left_node, right_node)
            else:
                # TODO: Make user defined exception for this
                raise Exception()

    def _type_error(self, node, msg, check, left_node, right_node):
        if check == "att_check":
            issue = TypeCheckerWarning(msg, self._policy, node.tpos(), node.token, left_node.token, right_node.token,
                                       check)
        else:
            issue = TypeCheckerError(msg, self._policy, node.tpos(), node.token, left_node.token, right_node.token,
                                     check)
        self._issues.append(issue)

    def _num_check(self, node):
        left_node = node.left()
        right_node = node.right()

        if left_node and right_node:
            if isinstance(left_node, StringValNode) or isinstance(right_node, StringValNode):
                self._type_error(node, "Type Error, strings can not be compared using inequality operations.",
                                 "num_check", left_node, right_node)
            elif isinstance(left_node, NullValNode) or isinstance(right_node, NullValNode):
                self._type_error(node, "Type Error, NULL value can not be compared using inequality operations.",
                                 "num_check", left_node, right_node)
            elif isinstance(left_node, AttNode) or isinstance(right_node, AttNode):
                self._att_check(node)
            elif isinstance(left_node, SetNode) or isinstance(right_node, SetNode):
                self._type_error(node, "Type Error, sets can not be compared using inequality operations.",
                                 "num_check", left_node, right_node)

        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def _eq_check(self, node):
        left_node = node.left()
        right_node = node.right()

        if left_node and right_node:
            if isinstance(left_node, AttNode) or isinstance(right_node, AttNode):
                self._att_check(node)
            elif (isinstance(left_node, NullValNode) and not isinstance(right_node, NullValNode)) or (
                        not isinstance(left_node, NullValNode) and isinstance(right_node, NullValNode)):
                self._type_error(node, "Type Error, NULL value can only be compared with other NULL values and "
                                       "attributes.", "eq_check", left_node, right_node)
            elif (isinstance(left_node, StringValNode) and not isinstance(right_node, StringValNode)) or (
                        not isinstance(left_node, StringValNode) and isinstance(right_node, StringValNode)):
                self._type_error(node, "Type Error, string values can only be compared with other string values and "
                                       "attributes.", "eq_check", left_node, right_node)
            elif (isinstance(left_node, SetNode) and not isinstance(right_node, SetNode)) or (
                        not isinstance(left_node, SetNode) and isinstance(right_node, SetNode)):
                self._type_error(node, "Type Error, sets can only be compared with other sets and "
                                       "attributes.", "eq_check", left_node, right_node)
        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def _in_check(self, node):
        left_node = node.left()
        right_node = node.right()

        if left_node and right_node:
            if isinstance(right_node, NullValNode):
                self._type_error(node, "Type Error, NULL value can only be used on the left hand side of IN "
                                       "operations.", "in_check", left_node, right_node)
            elif isinstance(left_node, SetNode):
                self._type_error(node, "Type Error, set values can only be used on the right hand side of IN "
                                       "operations.", "in_check", left_node, right_node)
            elif isinstance(right_node, StringValNode):
                self._type_error(node, "Type Error, string value can only be used on the left hand side of IN "
                                       "operations.", "in_check", left_node, right_node)
            elif isinstance(right_node, IntValNode):
                self._type_error(node, "Type Error, int value can only be used on the left hand side of IN "
                                       "operations.", "in_check", left_node, right_node)
            elif isinstance(right_node, FloatValNode):
                self._type_error(node, "Type Error, float value can only be used on the left hand side of IN "
                                       "operations.", "in_check", left_node, right_node)
        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def _subset_check(self, node):
        left_node = node.left()
        right_node = node.right()

        if left_node and right_node:
            if not ((isinstance(left_node, SetNode) or isinstance(left_node, AttNode)) and
                    (isinstance(right_node, SetNode) or isinstance(right_node, AttNode))):
                self._type_error(node, "Type Error, only sets and attributes can be compared using the SUBSET "
                                       "operation.", "subset_check", left_node, right_node)
        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def _op_node(self, node):
        if node.tvalue() in (">", "<", "<=", ">="):
            self._num_check(node)
        elif node.tvalue() in ("=", "!="):
            self._eq_check(node)
        elif node.tvalue().upper() == "IN":
            self._in_check(node)
        elif node.tvalue().upper() == "SUBSET":
            self._subset_check(node)
        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def _scan_tree(self, node):
        for n in node.children():
            if not isinstance(n, (SetNode, ValNode, BoolValNode)):
                self._scan_tree(n)

        if isinstance(node, AttNode):
            self._att_node(node)
        elif isinstance(node, OpNode):
            self._op_node(node)

    def get_errors(self):
        # TODO: raise error if check has not been run
        return list(filter(lambda x: x.type == ErrorType.ERROR, self._issues))

    def get_warnings(self):
        # TODO: raise error if check has not been run
        return list(filter(lambda x: x.type == ErrorType.WARN, self._issues))

    def get_result(self):
        if not self._checked:
            return TypeCheckerResult.NONE
        elif len(self._issues) == 0:
            return TypeCheckerResult.PASS
        elif any(x.type == ErrorType.ERROR for x in self._issues):
            return TypeCheckerResult.ERROR
        else:
            return TypeCheckerResult.WARN

    def get_issues(self):
        # TODO: raise error if check has not been run
        return self._issues[:]

    def get_symbol_table(self):
        return self._symbols

    def check(self, min_error_level=ErrorType.CRIT):
        # TODO: Reset if called 2nd time.
        self._scan_tree(self._ast)
        self._checked = True

        for error in self._issues:
            if error.type >= min_error_level:
                raise error

        return self._issues


class Optimizer(object):
    # TODO: Make policy optimizer
    pass
