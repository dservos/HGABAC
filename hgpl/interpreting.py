from hgpl.parsing import Parser
from hgpl.ast import ASTNode, AttNode, NotNode, SetNode, BoolOpNode, OpNode, ASTResult, ASTNullVal
from hgpl.symbols import SymbolTable, Symbol, SymbolType
from hgpl.errors import InterpreterError, InterpreterWarning


class Interpreter(object):
    def __init__(self, ast_or_parser, policy_text=None):
        self._symbols = None
        self._warnings = []

        if isinstance(ast_or_parser, Parser):
            self._parser = ast_or_parser
            self._ast = ast_or_parser.parse()
            self._policy = ast_or_parser.policy()
        elif isinstance(ast_or_parser, ASTNode):
            self._parser = None
            self._ast = ast_or_parser
            self._policy = policy_text

    def _warn(self, msg, rule, node=None, left=None, right=None):
        if node and isinstance(node, ASTNode):
            pos = node.tpos()
        elif left and isinstance(left, ASTNode):
            pos = left.tpos()
        elif right and isinstance(right, ASTNode):
            pos = right.tpos()
        else:
            pos = -1

        self._warnings.append(InterpreterWarning(msg, self._policy, pos, node, left, right, rule))

    def _error(self, msg, rule, node=None, left=None, right=None):
        if node and isinstance(node, ASTNode):
            pos = node.tpos()
        elif left and isinstance(left, ASTNode):
            pos = left.tpos()
        elif right and isinstance(right, ASTNode):
            pos = right.tpos()
        else:
            pos = -1

        raise InterpreterError(msg, self._policy, pos, node, left, right, rule)

    def _evaluate_att_node(self, node):
        symbol_name = Symbol.att_to_symbol_name(node)
        symbol = self._symbols.lookup(symbol_name)

        if symbol:
            if symbol.value is None:
                self._warn("Interpreter Warning, the attribute {} has no value.".format(symbol_name),
                           "evaluate_att_node", node)
                node.result = ASTResult.UNDEF
            if not symbol.check_val_type():
                self._warn("Interpreter Warning, the attribute {} has an invalid type.".format(symbol_name),
                           "evaluate_att_node", node)
                node.result = ASTResult.UNDEF
            elif symbol.type == SymbolType.BOOL:
                node.result = symbol.value
            else:
                node.result = symbol
        else:
            self._warn("Interpreter Warning, unknown attribute {} found in policy.".format(symbol_name),
                       "evaluate_att_node", node)
            node.result = ASTResult.UNDEF

    def _evaluate_not_node(self, node):
        if node.left() and node.left().result is not None and isinstance(node.left().result, ASTResult):
            node.result = ASTResult.tri_not(node.left().result)
        else:
            self._error("Interpreter Error, invalid child node or invalid child node result.", "evaluate_not_node",
                        node)

    def _evaluate_bool_op_node(self, node):
        left = node.left()
        right = node.right()

        if left and right and left.result is not None and right.result is not None and \
           isinstance(left.result, ASTResult) and isinstance(right.result, ASTResult) and \
           node.tvalue().upper() in ("AND", "OR"):
                if node.tvalue().upper() == "AND":
                    node.result = left.result & right.result
                else:
                    node.result = left.result | right.result
        else:
            self._error("Interpreter Error, invalid child node or invalid child node result.", "evaluate_bool_op_node",
                        node)

    def _symbol_to_val(self, symbol, other_val, mode):
        if isinstance(symbol.value, set):
            return symbol.value
        elif isinstance(symbol.value, list):
            return set(symbol.value)
        elif isinstance(other_val, (set, list)) or isinstance(other_val, Symbol):
            if mode == 0:
                return {symbol.value}
            elif mode == 1:
                return symbol.value
        else:
            return symbol.value

    def _eq_op(self, lresult, rresult):
        tmp = lresult
        if isinstance(lresult, Symbol):
            lresult = self._symbol_to_val(lresult, rresult, 0)

        if isinstance(rresult, Symbol):
            rresult = self._symbol_to_val(rresult, tmp, 0)

        if (isinstance(lresult, (int, float)) and isinstance(rresult, (int, float))) or \
           (isinstance(lresult, str) and isinstance(rresult, str)) or \
           (isinstance(lresult, set) and isinstance(rresult, set)) or \
           (isinstance(lresult, ASTNullVal) and isinstance(rresult, ASTNullVal)):
            return ASTResult.from_bool(lresult == rresult)
        elif isinstance(lresult, list) and isinstance(rresult, list):
            return ASTResult.from_bool(set(lresult) == set(rresult))
        else:
            self._warn("Interpreter Warning, invalid type used in '=' or '!=' operation.", "eq_op", None, lresult,
                       rresult)
            return ASTResult.UNDEF

    def _neq_op(self, lresult, rresult):
        return ASTResult.tri_not(self._eq_op(lresult, rresult))

    def _gt_op(self, lresult, rresult):
        if isinstance(lresult, Symbol):
            lresult = lresult.value

        if isinstance(rresult, Symbol):
            rresult = rresult.value

        if isinstance(lresult, (int, float)) and isinstance(rresult, (int, float)):
            return ASTResult.from_bool(lresult > rresult)
        else:
            self._warn("Interpreter Warning, invalid type used in '>' operation.", "qt_op", None, lresult, rresult)
            return ASTResult.UNDEF

    def _lt_op(self, lresult, rresult):
        if isinstance(lresult, Symbol):
            lresult = lresult.value

        if isinstance(rresult, Symbol):
            rresult = rresult.value

        if isinstance(lresult, (int, float)) and isinstance(rresult, (int, float)):
            return ASTResult.from_bool(lresult < rresult)
        else:
            self._warn("Interpreter Warning, invalid type used in '<' operation.", "lt_op", None, lresult, rresult)
            return ASTResult.UNDEF

    def _gte_op(self, lresult, rresult):
        if isinstance(lresult, Symbol):
            lresult = lresult.value

        if isinstance(rresult, Symbol):
            rresult = rresult.value

        if isinstance(lresult, (int, float)) and isinstance(rresult, (int, float)):
            return ASTResult.from_bool(lresult >= rresult)
        else:
            self._warn("Interpreter Warning, invalid type used in '>=' operation.", "gte_op", None, lresult, rresult)
            return ASTResult.UNDEF

    def _lte_op(self, lresult, rresult):
        if isinstance(lresult, Symbol):
            lresult = lresult.value

        if isinstance(rresult, Symbol):
            rresult = rresult.value

        if isinstance(lresult, (int, float)) and isinstance(rresult, (int, float)):
            return ASTResult.from_bool(lresult <= rresult)
        else:
            self._warn("Interpreter Warning, invalid type used in '<=' operation.", "lte_op", None, lresult, rresult)
            return ASTResult.UNDEF

    def _in_op(self, lresult, rresult):
        tmp = lresult
        if isinstance(lresult, Symbol):
            lresult = self._symbol_to_val(lresult, rresult, 1)

        if isinstance(rresult, Symbol):
            rresult = self._symbol_to_val(rresult, tmp, 0)

        if isinstance(rresult, (set, list)):
            if isinstance(lresult, (int, float, str)):
                return ASTResult.from_bool(lresult in rresult)
            elif isinstance(lresult, ASTNullVal):
                return ASTResult.from_bool(ASTNullVal() in rresult)
            elif isinstance(lresult, (set, list)):
                return ASTResult.from_bool(any(x in lresult for x in rresult))

        self._warn("Interpreter Warning, invalid type used in 'IN' operation.", "in_op", None, lresult, rresult)
        return ASTResult.UNDEF

    def _subset_op(self, lresult, rresult):
        tmp = lresult
        if isinstance(lresult, Symbol):
            lresult = self._symbol_to_val(lresult, rresult, 0)
        elif isinstance(lresult, list):
            lresult = set(lresult)

        if isinstance(rresult, Symbol):
            rresult = self._symbol_to_val(rresult, tmp, 0)
        elif isinstance(rresult, list):
            rresult = set(rresult)

        if isinstance(lresult, set) and isinstance(rresult, set):
            return ASTResult.from_bool(lresult.issubset(rresult))
        else:
            self._warn("Interpreter Warning, invalid type used in 'SUBSET' operation.", "subset_op", None, lresult,
                       rresult)
            return ASTResult.UNDEF

    def _evaluate_op_node(self, node):
        left = node.left()
        right = node.right()

        if left and right and left.result is not None and right.result is not None and \
           node.tvalue().upper() in ("=", "!=", "<", ">", "<=", ">=", "IN", "SUBSET"):
            lresult = left.result
            rresult = right.result

            if lresult == ASTResult.UNDEF or rresult == ASTResult.UNDEF:
                node.result = ASTResult.UNDEF
                return

            if node.tvalue() == "=":
                node.result = self._eq_op(lresult, rresult)
            elif node.tvalue() == "!=":
                node.result = self._neq_op(lresult, rresult)
            elif node.tvalue() == ">":
                node.result = self._gt_op(lresult, rresult)
            elif node.tvalue() == "<":
                node.result = self._lt_op(lresult, rresult)
            elif node.tvalue() == ">=":
                node.result = self._gte_op(lresult, rresult)
            elif node.tvalue() == "<=":
                node.result = self._lte_op(lresult, rresult)
            elif node.tvalue().upper() == "IN":
                node.result = self._in_op(lresult, rresult)
            elif node.tvalue().upper() == "SUBSET":
                node.result = self._subset_op(lresult, rresult)
            else:
                self._error("Interpreter Error, invalid operation.", "evaluate_op_node", node)
        else:
            self._error("Interpreter Error, invalid child node or invalid child node result.", "evaluate_op_node", node)

    def _evaluate_set_node(self, node):
        node.result = []
        for n in node.children():
            if n.result and isinstance(n.result, (int, float, str, ASTNullVal)):
                    node.result.append(n.result)
            else:
                self._error("Interpreter Error, invalid child node or invalid child node result.", "evaluate_set_node",
                            node)

    def _evaluate_node(self, node):
        for n in node.children():
            if not n.result:
                self._evaluate_node(n)

        if isinstance(node, AttNode):
            self._evaluate_att_node(node)
        elif isinstance(node, NotNode):
            self._evaluate_not_node(node)
        elif isinstance(node, SetNode):
            self._evaluate_set_node(node)
        elif isinstance(node, BoolOpNode):
            self._evaluate_bool_op_node(node)
        elif isinstance(node, OpNode):
            self._evaluate_op_node(node)
        else:
            self._error("Interpreter Error, invalid node type.", "evaluate_node", node)

    def get_warnings(self):
        return self._warnings[:]

    def evaluate(self, att_symbol_table=None, min_warn_level=None):
        if att_symbol_table:
            self._symbols = att_symbol_table
        else:
            self._symbols = SymbolTable()

        self._evaluate_node(self._ast)

        for warn in self._warnings:
            if warn.type >= min_warn_level:
                raise warn

        return self._ast.result
