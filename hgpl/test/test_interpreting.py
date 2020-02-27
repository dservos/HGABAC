import unittest
from unittest import TestCase

from hgpl.symbols import SymbolType, SymbolTable, SymbolTableBuilder
from hgpl.lexing import Lexer
from hgpl.parsing import Parser
from hgpl.semantics import TypeChecker
from hgpl.errors import ErrorType
from hgpl.interpreting import Interpreter
from hgpl.ast import ASTResult

import time


class TestInterpreter(TestCase):
    DEBUG = False
    PROFILE = False
    PROFILE_COUNT = 10000

    def _build_symbol_table(self):
        types = {"user.id": SymbolType.INT,
                 "object.owner": SymbolType.INT,
                 "object.required_perms": SymbolType.SET,
                 "user.perms": SymbolType.SET,
                 "user.age": SymbolType.INT,
                 "user.admin": SymbolType.BOOL,
                 "user.role": SymbolType.STRING,
                 "object.patient": SymbolType.INT,
                 "user.user_type": SymbolType.SET,
                 "object.object_type": SymbolType.STRING,
                 "object.restricted": SymbolType.BOOL,
                 "user.enrolled_in": SymbolType.SET,
                 "object.req_course": SymbolType.SET,
                 "user.teaching": SymbolType.SET,
                 "object.depart": SymbolType.SET,
                 "user.depart": SymbolType.SET,
                 "env.time_of_day_hour": SymbolType.INT,
                 "env.day_of_week": SymbolType.INT,
                 "connect.ip_octet_1": SymbolType.INT,
                 "connect.ip_octet_2": SymbolType.INT,
                 "connect.ip_octet_3": SymbolType.INT,
                 "connect.ip_octet_4": SymbolType.INT,
                 "user.string": SymbolType.STRING,
                 "user.float": SymbolType.FLOAT,
                 "user.int": SymbolType.INT,
                 "user.set": SymbolType.SET}

        sb = SymbolTableBuilder(types)

        vals = {"user.id": 1337,
                 "object.owner": 1337,
                 "object.required_perms": {1, 5, 3},
                 "user.perms": {2, 5, 4, 3, 0, 1},
                 "user.age": 30,
                 "user.admin": True,
                 "user.role": "admin",
                 "object.patient": 1337,
                 "user.user_type": {"admin", "grad", "staff"},
                 "object.object_type": "book",
                 "object.restricted": False,
                 "user.enrolled_in": {"CS1032", "CS2034"},
                 "object.req_course": {"CS4030", "CS2034"},
                 "user.teaching": {"CS3090", "CS1032"},
                 "object.depart": {"COMPSCI", "SOFTENG"},
                 "user.depart": {"COMPSCI"},
                 "env.time_of_day_hour": 9,
                 "env.day_of_week": 4,
                 "connect.ip_octet_1": 192,
                 "connect.ip_octet_2": 168,
                 "connect.ip_octet_3": 1,
                 "connect.ip_octet_4": 110,
                 "user.string": "hello world",
                 "user.float": 3.14,
                 "user.int": 3,
                 "user.set": {1, 2, 3}}

        sb.load_mixed_att_val_dict(vals)
        return sb.build()

    def _evaluate_policy(self, policy_text, symbol_table, result):
        if TestInterpreter.PROFILE:
            test_result = None
            ast = None
            t0 = time.time()
            for i in range(0, TestInterpreter.PROFILE_COUNT):
                lex = Lexer(policy_text)
                p = Parser(lex)
                ast = p.parse()
                tc = TypeChecker(ast, policy_text)
                tc.check(ErrorType.ERROR)
                i = Interpreter(ast, policy_text)
                test_result = i.evaluate(symbol_table, ErrorType.ERROR)
            t1 = time.time()
            self.assertEqual(result, test_result)
            print("\nPolicy: %s\nPolicy evaluation took: %s seconds\nAST size was: %d nodes.\n" % (policy_text,
                                                                                               str(t1 - t0),
                                                                                               ast.calc_num_nodes()))
        else:
            lex = Lexer(policy_text)
            p = Parser(lex)
            ast = p.parse()
            tc = TypeChecker(ast, policy_text)
            tc.check(ErrorType.ERROR)
            i = Interpreter(ast, policy_text)
            test_result = i.evaluate(symbol_table, ErrorType.ERROR)
            self.assertEqual(result, test_result)


    def _debug_policy_eval(self, policy_text, symbol_table):
        if TestInterpreter.DEBUG:
            print("Policy: " + policy_text)
            lex = Lexer(policy_text)
            p = Parser(lex)
            ast = p.parse()
            tc = TypeChecker(ast, policy_text)
            tc.check(ErrorType.NONE)
            try:
                i = Interpreter(ast, policy_text)
                test_result = i.evaluate(symbol_table, ErrorType.NONE)
                print("Result: " + str(test_result))
            finally:
                print("\nAST:")
                print(str(ast))

    # TODO: Test whole trees not just results.
    # TODO: Remove debugging.

    def test_hgabac_paper_ex_a(self):
        p = "user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.TRUE)

    def test_hgabac_paper_ex_b(self):
        p = "object.required_perms SUBSET user.perms AND user.age >= 18"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.TRUE)

    def test_hgabac_paper_ex_c(self):
        p = "user.admin OR (user.role = \"doctor\" AND user.id != object.patient)"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.TRUE)

    def test_hgabac_paper_ex_c_with_parn_inverted(self):
        p = "(user.admin OR user.role = \"doctor\") AND user.id != object.patient"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.FALSE)

    def test_hgabac_paper_case_1(self):
        p = "\"undergrad\" IN user.user_type AND ((object.object_type = \"book\" AND NOT object.restricted) OR " \
                 "(object.object_type = \"course\" AND user.enrolled_in IN object.req_course))"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.FALSE)

    def test_hgabac_paper_case_2(self):
        p = "\"grad\" IN user.user_type AND (object.object_type = \"periodical\" OR (object.object_type " \
                 "=\"course\" AND object.req_course IN user.teaching))"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.FALSE)

    def test_hgabac_paper_case_3(self):
        p = "\"faculty\" IN user.user_type AND(object.object_type IN {\"book\", \"periodical\", \"course\"} OR " \
                 "(object.object_type = \"archive\" AND object.depart IN user.depart))"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.FALSE)

    def test_hgabac_paper_case_4(self):
        p = "\"staff\" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND " \
                 "env.day_of_week IN {2, 3, 4, 5, 6}"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.TRUE)

    def test_hgabac_paper_case_5(self):
        p = "\"cs_course\" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND " \
                 "object.object_type = \"periodical\""
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.FALSE)

    def test_sets_in(self):
        p = "\"CS1032\" IN user.enrolled_in AND user.enrolled_in IN user.enrolled_in AND user.enrolled_in IN {\"CS3090\", \"CS1032\", \"CS1234\"}"
        st = self._build_symbol_table()
        self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.TRUE)

    def test_missing_att(self):
        p = "user.not_an_existing_att_name = 42"
        st = self._build_symbol_table()
        #self._debug_policy_eval(p, st)
        self._evaluate_policy(p, st, ASTResult.UNDEF)


# TODO: Add this kind of line to other test files.
if __name__ == '__main__':
    unittest.main()