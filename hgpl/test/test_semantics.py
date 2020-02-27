from unittest import TestCase

from hgpl.semantics import TypeChecker, TypeCheckerResult
from hgpl.parsing import Parser
from hgpl.lexing import *
from hgpl.errors import TypeCheckerError


class TestTypeChecker (TestCase):
    # TODO: Test symbol table creation
    # TODO: Test public class methods and init
    # TODO: Better testing of errors
    # TODO: More complex tests
    # TODO: Add test for attribute chains once working in type checker

    @staticmethod
    def _make_type_checker_from_policy(policy_text):
        lex = Lexer(policy_text)
        p = Parser(lex)
        ast = p.parse()
        tc = TypeChecker(ast, policy_text)
        return tc

    @staticmethod
    def _debug_type_check(policy_text):
        print("Policy: " + policy_text)
        tc = TestTypeChecker._make_type_checker_from_policy(policy_text)
        tc.check()
        print("Type Check Result: " + tc.get_result().name)

        errors = tc.get_errors()
        warns = tc.get_warnings()

        if errors:
            print("\nErrors:")
            for e in errors:
                print(str(e))

        if warns:
            print("\nWarnings:")
            for w in warns:
                print(str(w))

    def _check_policy_passed(self, policy_text):
        tc = TestTypeChecker._make_type_checker_from_policy(policy_text)
        tc.check()
        self.assertEqual(tc.get_result(), TypeCheckerResult.PASS)

    def _check_policy_errors(self, policy_text, num_errors, num_warnings, checks, result):
        # TODO: Also check pos and tokens.
        tc = TestTypeChecker._make_type_checker_from_policy(policy_text)
        issues = tc.check()
        self.assertEqual(result, tc.get_result())
        errors = tc.get_errors()
        warns = tc.get_warnings()
        self.assertEqual(num_errors, len(errors))
        self.assertEqual(num_warnings, len(warns))
        for i in issues:
            self.assertTrue(isinstance(i, TypeCheckerError))
            self.assertTrue(i.check == checks or i.check in checks, "{} is not in or equal to {}".format(i.check,
                                                                                                         str(checks)))

    def test_simp_ok_atts(self):
        p1 = 'env.a = "cat" and env.a != "dog" or 1.234 = env.b and 5.4234 != env.b'
        p2 = 'env.a > 5 and env.a < 1.234 or -1 >= env.a and -0.123 <= env.a or env.a = 0 and env.a != 123.123'
        p3 = 'env.a = {1,2,3} and env.a != {} or {"cat", "dog"} subset env.a and env.a subset {1, 1.234}'
        p4 = '{1,2,3} = env.a and {} != env.a or env.b in {1, 1.234}'
        p5 = 'env.a = NULL or env.a != NULL and NULL = env.b and NULL != env.b'
        p6 = '"cat" in env.a and 1 in env.b and 1.234 in env.b and NULL in env.c'

        self._check_policy_passed(p1)
        self._check_policy_passed(p2)
        self._check_policy_passed(p3)
        self._check_policy_passed(p4)
        self._check_policy_passed(p5)
        self._check_policy_passed(p6)

    def test_ok_ops(self):
        p1 = '1 > 1.235 or 1.234 < 0 or 6 >= -1.234 or 0.034 <= -10 or 100 = 0.0101 or -100.100 != -100'
        p2 = '1 > 12 or 1 < 0 or 6 >= -1 or 34 <= -10 or 100 = 101 or -100 != -100'
        p3 = '1.12 > 1.235 or 1.234 < 0.0 or 6.0 >= -1.234 or 0.034 <= -10.10 or 100.0101 = 0.0101 or ' \
             '-100.100 != -100.01'
        p4 = '"cat" = "dog" or "cat" != "dog"'
        p5 = 'NULL = NULL and NULL != NULL'
        p6 = '{} = {123} or {1,2,3} != {"a", "b", "c"}'
        p7 = '1 IN {1,2,3} or 1.234 IN {1.1, 2.2, 3.3} or "cat" in {} or NULL in {NULL, 1, "dog"}'
        p8 = '{} SUBSET {1} or {"cat"} SUBSET {"cat", "dog"} or {1,2,3} SUBSET {1.1, 2.2}'

        self._check_policy_passed(p1)
        self._check_policy_passed(p2)
        self._check_policy_passed(p3)
        self._check_policy_passed(p4)
        self._check_policy_passed(p5)
        self._check_policy_passed(p6)
        self._check_policy_passed(p7)
        self._check_policy_passed(p8)

    def test_simp_att_type_errors(self):
        p1 = 'env.a = "cat" and env.a < 5 or env.b > "cat" and env.b = 5.5 and env.c > NULL and env.d <= NULL'
        p2 = 'env.a >= {} or env.a != 5 and env.b <= {1,2} or env.b > "dog"'
        p3 = 'env.a != {"a"} and env.a < 1.123 or env.b > 1.234 and env.b >= "cat"'
        p4 = '5.5 = env.b or "cat" = env.a and 5 < env.a or "cat" != env.b'
        p5 = '{} >= env.a or "dog" != env.b or 5 != env.a and {1,2} <= env.b'
        p6 = '1.123 < env.a or 1.234 > env.b and "cat" = env.b or NULL != env.a'
        p7 = '{} in env.a and {1} in env.b and {1.2, 2.1} in env.c'

        self._check_policy_errors(p1, 3, 1, ("att_check", "num_check"), TypeCheckerResult.ERROR)
        self._check_policy_errors(p2, 1, 1, ("att_check", "num_check"), TypeCheckerResult.ERROR)
        self._check_policy_errors(p3, 1, 1, ("att_check", "num_check"), TypeCheckerResult.ERROR)
        self._check_policy_errors(p4, 0, 2, "att_check", TypeCheckerResult.WARN)
        self._check_policy_errors(p5, 0, 2, "att_check", TypeCheckerResult.WARN)
        self._check_policy_errors(p6, 0, 2, "att_check", TypeCheckerResult.WARN)
        self._check_policy_errors(p7, 3, 0, "in_check", TypeCheckerResult.ERROR)

    def test_op_subset_type_errors(self):
        p1 = '"cat" SUBSET 5 and "dog" SUBSET 1.2 or "dan" SUBSET {1,2,3} and "bob" SUBSET NULL or -123 SUBSET "bob" ' \
             'or 0.43 SUBSET "alice" and {1.2, 3.4, 5.6} SUBSET "hello" and NULL SUBSET "world" and "string" SUBSET' \
             ' "string"'
        p2 = '1234 SUBSET NULL and -123.34 SUBSET NULL or {1.23, 4.56, 6.3} SUBSET NULL and "hello world" SUBSET NULL' \
             ' or NULL SUBSET 1234 and  NULL SUBSET -123.34 or NULL SUBSET {1.23, 4.56, 6.3} and NULL SUBSET ' \
             '"hello world" and NULL SUBSET NULL'
        p3 = '{} SUBSET 1 and {1} SUBSET 4.5 and {1,2} SUBSET "cat" and {1.1,2.2} SUBSET NULL or ' \
             '1 SUBSET {"cat","dog"} and 0.123 SUBSET {1.2} and "string" SUBSET {NULL} and NULL SUBSET {}'

        self._check_policy_errors(p1, 9, 0, "subset_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p2, 9, 0, "subset_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p3, 8, 0, "subset_check", TypeCheckerResult.ERROR)

    def test_op_in_type_errors(self):
        p1 = '"cat" IN 5 and "dog" IN 1.2 or "bob" IN NULL or -123 IN "bob" or 0.43 IN "alice" and ' \
             '{1.2, 3.4, 5.6} IN "hello" and NULL IN "world" and "string" IN "string"'
        p2 = '1234 IN NULL and -123.34 IN NULL or {1.23, 4.56, 6.3} IN NULL and "hello world" IN NULL or ' \
             'NULL IN 1234 and  NULL IN -123.34 and NULL IN "hello world" and NULL IN NULL'
        p3 = '{} IN 1 and {1} IN 4.5 and {1,2} IN "cat" and {1.1,2.2} IN NULL and {"a"} IN {"b"}'

        self._check_policy_errors(p1, 8, 0, "in_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p2, 8, 0, "in_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p3, 5, 0, "in_check", TypeCheckerResult.ERROR)

    def test_op_eq_type_errors(self):
        p1 = '"cat" = 5 and "dog" != 1.2 or "dan" = {1,2,3} and "bob" != NULL or -123 = "bob" or 0.43 != "alice" and ' \
             '{1.2, 3.4, 5.6} = "hello" and NULL != "world"'
        p2 = '1234 = NULL and -123.34 = NULL or {1.23, 4.56, 6.3} != NULL and "hello world" != NULL or ' \
             'NULL = 1234 and  NULL = -123.34 or NULL != {1.23, 4.56, 6.3} and NULL != "hello world"'
        p3 = '{} = 1 and {1} != 4.5 and {1,2} = "cat" and {1.1,2.2} != NULL or 1 = {"cat","dog"} and ' \
             '0.123 != {1.2} and "string" = {NULL} and NULL != {}'

        self._check_policy_errors(p1, 8, 0, "eq_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p2, 8, 0, "eq_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p3, 8, 0, "eq_check", TypeCheckerResult.ERROR)

    def test_op_num_type_errors(self):
        p1 = '"cat" <= 5 and "dog" >= 1.2 or "dan" < {1,2,3} and "bob" > NULL or -123 > "bob" or 0.43 < "alice" and ' \
             '{1.2, 3.4, 5.6} >= "hello" and NULL <= "world" and "string" > "string"'
        p2 = '1234 <= NULL and -123.34 >= NULL or {1.23, 4.56, 6.3} < NULL and "hello world" > NULL or ' \
             'NULL <= 1234 and  NULL >= -123.34 or NULL < {1.23, 4.56, 6.3} and NULL > "hello world" and NULL < NULL'
        p3 = '{} > 1 and {1} < 4.5 and {1,2} >= "cat" and {1.1,2.2} <= NULL or 1 < {"cat","dog"} and ' \
             '0.123 > {1.2} and "string" >= {NULL} and NULL <= {} and {1,2,3} > {"a", "b", "c"}'

        self._check_policy_errors(p1, 9, 0, "num_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p2, 9, 0, "num_check", TypeCheckerResult.ERROR)
        self._check_policy_errors(p3, 9, 0, "num_check", TypeCheckerResult.ERROR)

    def test_hgabac_paper_ex_a(self):
        p = "user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner"
        self._check_policy_passed(p)

    def test_hgabac_paper_ex_b(self):
        p = "object.required_perms SUBSET user.perms AND user.age >= 18"
        self._check_policy_passed(p)

    def test_hgabac_paper_ex_c(self):
        p = "user.admin OR (user.role = \"doctor\" AND user.id != object.patient)"
        self._check_policy_passed(p)

    def test_hgabac_paper_case_1(self):
        p = "\"undergrad\" IN user.user_type AND ((object.object_type = \"book\" AND NOT object.restricted) OR " \
                 "(object.object_type = \"course\" AND user.enrolled_in IN object.req_course))"
        self._check_policy_passed(p)

    def test_hgabac_paper_case_2(self):
        p = "\"grad\" IN user.user_type AND (object.object_type = \"periodical\" OR (object.object_type " \
                 "=\"course\" AND object.req_course IN user.teaching))"
        self._check_policy_passed(p)

    def test_hgabac_paper_case_3(self):
        p = "\"faculty\" IN user.user_type AND(object.object_type IN {\"book\", \"periodical\", \"course\"} OR " \
                 "(object.object_type = \"archive\" AND object.depart IN user.depart))"
        self._check_policy_passed(p)

    def test_hgabac_paper_case_4(self):
        p = "\"staff\" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND " \
                 "env.day_of_week IN {2, 3, 4, 5, 6}"
        self._check_policy_passed(p)

    def test_hgabac_paper_case_5(self):
        p = "\"cs_course\" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND " \
                 "object.object_type = \"periodical\""
        self._check_policy_passed(p)


class TestOptimizer (TestCase):
    # TODO: Unit tests for optimizer
    pass