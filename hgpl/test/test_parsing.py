from unittest import TestCase

from hgpl.parsing import Parser
from hgpl.lexing import *
from hgpl.ast import *
from hgpl.errors import ParserError


class TestParser(TestCase):
    @staticmethod
    def _debug_output(policy_text):
        lex = Lexer(policy_text)
        p = Parser(lex)
        test_ast = p.parse()
        print("Policy: " + policy_text)
        print("AST:")
        print(test_ast)
        print("repr(AST):")
        print(repr(test_ast))

    def _check_using_policy(self, policy_text, correct_ast):
        lex = Lexer(policy_text)
        p = Parser(lex)
        test_ast = p.parse()
        self.assertEqual(correct_ast, test_ast)

    def _check_error_using_policy(self, policy_text, token, pos, rule):
        with self.assertRaises(ParserError) as cm:
            lex = Lexer(policy_text)
            p = Parser(lex)
            p.parse()
        self.assertEqual(pos, cm.exception.pos)
        self.assertEqual(rule, cm.exception.rule)
        self.assertEqual(token, cm.exception.token)

    # TODO: More error test
    # TODO: Unit test coverings other functions of the Parser class (not just the parse method)

    def test_set_errors(self):
        p1 = '{TRUE} = env.a'
        p2 = '{1, FALSE} = env.b'
        p3 = '{1, UNDEF, 3} = env.c'
        p4 = '{1, TRUE} = env.d'
        p5 = '{AND} = env.e'
        p6 = '{5.5, OR} = env.f'
        p7 = '{NOT, -4.5} = env.g'
        p8 = '{=} = env.h'
        p9 = '{1, IN} = env.i'
        p10 = '{SUBSET, "cat"} = env.j'
        p11 = '{1, >=, 2} = env.k'
        p12 = '{user.1} = env.l'
        p13 = '{1, env.1} = env.m'
        p14 = '{object.1, 2} = env.n'
        p15 = '{1, admin.1, 2} = env.o'
        p16 = '{,} = env.p'
        p17 = '{,,} = env.q'
        p18 = '{1,} = env.r'
        p19 = '{,1} = env.s'
        p20 = '{1 1} = env.t'
        p21 = '{(1)} = env.u'

        self._check_error_using_policy(p1, Token(TokenType.BOOL, 1, "TRUE"), 1, "atomic")
        self._check_error_using_policy(p2, Token(TokenType.BOOL, 4, "FALSE"), 4, "atomic")
        self._check_error_using_policy(p3, Token(TokenType.BOOL, 4, "UNDEF"), 4, "atomic")
        self._check_error_using_policy(p4, Token(TokenType.BOOL, 4, "TRUE"), 4, "atomic")
        self._check_error_using_policy(p5, Token(TokenType.BOOL_OP, 1, "AND"), 1, "atomic")
        self._check_error_using_policy(p6, Token(TokenType.BOOL_OP, 6, "OR"), 6, "atomic")
        self._check_error_using_policy(p7, Token(TokenType.NOT_OP, 1, "NOT"), 1, "atomic")
        self._check_error_using_policy(p8, Token(TokenType.OP, 1, "="), 1, "atomic")
        self._check_error_using_policy(p9, Token(TokenType.OP, 4, "IN"), 4, "atomic")
        self._check_error_using_policy(p10, Token(TokenType.OP, 1, "SUBSET"), 1, "atomic")
        self._check_error_using_policy(p11, Token(TokenType.OP, 4, ">="), 4, "atomic")
        self._check_error_using_policy(p12, Token(TokenType.USR_ATT, 1, "1"), 1, "atomic")
        self._check_error_using_policy(p13, Token(TokenType.ENV_ATT, 4, "1"), 4, "atomic")
        self._check_error_using_policy(p14, Token(TokenType.OBJ_ATT, 1, "1"), 1, "atomic")
        self._check_error_using_policy(p15, Token(TokenType.ADM_ATT, 4, "1"), 4, "atomic")
        self._check_error_using_policy(p16, Token(TokenType.COMMA, 1), 1, "atomic")
        self._check_error_using_policy(p17, Token(TokenType.COMMA, 1), 1, "atomic")
        self._check_error_using_policy(p18, Token(TokenType.RSET, 3), 3, "atomic")
        self._check_error_using_policy(p19, Token(TokenType.COMMA, 1), 1, "atomic")
        self._check_error_using_policy(p20, Token(TokenType.INT, 3, 1), 3, "set")
        self._check_error_using_policy(p21, Token(TokenType.LPARN, 1,), 1, "atomic")

    def test_parn_errors(self):
        p1 = '(user.missing_parn_right'
        p2 = 'user.missing_parn_left)'
        p3 = 'user.AND_parns (AND) admin.AND_parns'
        p4 = '(env.mixmatch_parns_left() OR object.mixmatch_parns_left)'
        p5 = '(env.mixmatch_parns_right OR ()object.mixmatch_parns_right)'
        p6 = '()'
        p7 = 'env.empty_parns AND ()'
        p8 = 'NOT ()'
        p9 = '(((TRUE AND FALSE) OR TRUE) AND UNDEF'
        p10 = 'TRUE AND (FALSE OR (TRUE AND UNDEF)))'
        p11 = 'TRUE AND ((FALSE OR TRUE) AND UNDEF'
        p12 = 'TRUE AND (FALSE OR TRUE)) AND UNDEF'

        self._check_error_using_policy(p1, Token(TokenType.END, 24), 24, "exp")
        self._check_error_using_policy(p2, Token(TokenType.RPARN, 22), 22, "parse")
        self._check_error_using_policy(p3, Token(TokenType.LPARN, 15), 15, "parse")
        self._check_error_using_policy(p4, Token(TokenType.LPARN, 24), 24, "exp")
        self._check_error_using_policy(p5, Token(TokenType.RPARN, 30), 30, "exp")
        self._check_error_using_policy(p6, Token(TokenType.RPARN, 1), 1, "exp")
        self._check_error_using_policy(p7, Token(TokenType.RPARN, 21), 21, "exp")
        self._check_error_using_policy(p8, Token(TokenType.RPARN, 5), 5, "exp")
        self._check_error_using_policy(p9, Token(TokenType.END, 37), 37, "exp")
        self._check_error_using_policy(p10, Token(TokenType.RPARN, 36), 36, "parse")
        self._check_error_using_policy(p11, Token(TokenType.END, 35), 35, "exp")
        self._check_error_using_policy(p10, Token(TokenType.RPARN, 36), 36, "parse")

    def test_bool_op_errors(self):
        p1 = 'TRUE = FALSE'
        p2 = 'UNDEF >= TRUE'
        p3 = 'FALSE <= UNDEF'
        p4 = 'UNDEF > UNDEF'
        p5 = 'FALSE < FALSE'
        p6 = 'TRUE != TRUE'
        p7 = 'TRUE IN FALSE'
        p8 = 'FALSE SUBSET TRUE'
        p9 = 'AND = OR'
        p10 = 'user.a >= OR'
        p11 = 'AND <= user.b'
        p12 = 'NOT IN 5'
        p13 = '8.8 IN NOT'
        p14 = '"cat" > FALSE'
        p15 = 'TRUE < "dog"'
        p16 = 'NOT(TRUE) != env.a'
        p17 = 'env.b = NOT(FALSE)'
        p18 = 'NOT(AND)'
        p19 = 'NOT(OR)'
        p20 = 'NOT(NOT)'
        p21 = 'NOT(NOT())'

        self._check_error_using_policy(p1, Token(TokenType.OP, 5, "="), 5, "parse")
        self._check_error_using_policy(p2, Token(TokenType.OP, 6, ">="), 6, "parse")
        self._check_error_using_policy(p3, Token(TokenType.OP, 6, "<="), 6, "parse")
        self._check_error_using_policy(p4, Token(TokenType.OP, 6, ">"), 6, "parse")
        self._check_error_using_policy(p5, Token(TokenType.OP, 6, "<"), 6, "parse")
        self._check_error_using_policy(p6, Token(TokenType.OP, 5, "!="), 5, "parse")
        self._check_error_using_policy(p7, Token(TokenType.OP, 5, "IN"), 5, "parse")
        self._check_error_using_policy(p8, Token(TokenType.OP, 6, "SUBSET"), 6, "parse")

        self._check_error_using_policy(p9, Token(TokenType.BOOL_OP, 0, "AND"), 0, "exp")
        self._check_error_using_policy(p10, Token(TokenType.BOOL_OP, 10, "OR"), 10, "var")
        self._check_error_using_policy(p11, Token(TokenType.BOOL_OP, 0, "AND"), 0, "exp")
        self._check_error_using_policy(p12, Token(TokenType.OP, 4, "IN"), 4, "att_name")
        self._check_error_using_policy(p13, Token(TokenType.NOT_OP, 7, "NOT"), 7, "var")
        self._check_error_using_policy(p14, Token(TokenType.BOOL, 8, "FALSE"), 8, "var")
        self._check_error_using_policy(p15, Token(TokenType.OP, 5, "<"), 5, "parse")
        self._check_error_using_policy(p16, Token(TokenType.OP, 10, "!="), 10, "parse")
        self._check_error_using_policy(p17, Token(TokenType.NOT_OP, 8, "NOT"), 8, "var")
        self._check_error_using_policy(p18, Token(TokenType.BOOL_OP, 4, "AND"), 4, "exp")
        self._check_error_using_policy(p19, Token(TokenType.BOOL_OP, 4, "OR"), 4, "exp")
        self._check_error_using_policy(p20, Token(TokenType.RPARN, 7), 7, "att_name")
        self._check_error_using_policy(p21, Token(TokenType.RPARN, 8), 8, "exp")

    def test_ops(self):
        p1 = 'env.a = 0 OR env.b > 1 OR env.c < 2 OR env.d <= 3 OR env.e >= 4 OR env.f != 5'
        ast1 = BoolOpNode(Token(TokenType.BOOL_OP, 64, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 50, 'OR'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 36, 'OR'),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 23, 'OR'),
                                                           BoolOpNode(Token(TokenType.BOOL_OP, 10, 'OR'),
                                                                      OpNode(Token(TokenType.OP, 6, '='),
                                                                             EnvAttNode(Token(TokenType.ENV_ATT, 0, 'a')),
                                                                             IntValNode(Token(TokenType.INT, 8, 0))),
                                                                      OpNode(Token(TokenType.OP, 19, '>'),
                                                                             EnvAttNode(Token(TokenType.ENV_ATT, 13, 'b')),
                                                                             IntValNode(Token(TokenType.INT, 21, 1)))),
                                                           OpNode(Token(TokenType.OP, 32, '<'),
                                                                  EnvAttNode(Token(TokenType.ENV_ATT, 26, 'c')),
                                                                  IntValNode(Token(TokenType.INT, 34, 2)))),
                                                OpNode(Token(TokenType.OP, 45, '<='),
                                                       EnvAttNode(Token(TokenType.ENV_ATT, 39, 'd')),
                                                       IntValNode(Token(TokenType.INT, 48, 3)))),
                                     OpNode(Token(TokenType.OP, 59, '>='),
                                            EnvAttNode(Token(TokenType.ENV_ATT, 53, 'e')),
                                            IntValNode(Token(TokenType.INT, 62, 4)))),
                          OpNode(Token(TokenType.OP, 73, '!='),
                                 EnvAttNode(Token(TokenType.ENV_ATT, 67, 'f')),
                                 IntValNode(Token(TokenType.INT, 76, 5))))

        p2 = 'env.a = env._a OR env.b > env._b OR env.c < env._c OR env.d <= env._d OR env.e >= env._e OR env.f ' \
             '!= env._f'
        ast2 = BoolOpNode(Token(TokenType.BOOL_OP, 89, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 70, 'OR'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 51, 'OR'),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 33, 'OR'),
                                                           BoolOpNode(Token(TokenType.BOOL_OP, 15, 'OR'),
                                                                      OpNode(Token(TokenType.OP, 6, '='),
                                                                             EnvAttNode(Token(TokenType.ENV_ATT, 0, 'a')),
                                                                             EnvAttNode(Token(TokenType.ENV_ATT, 8, '_a'))),
                                                                      OpNode(Token(TokenType.OP, 24, '>'),
                                                                             EnvAttNode(Token(TokenType.ENV_ATT, 18, 'b')),
                                                                             EnvAttNode(Token(TokenType.ENV_ATT, 26, '_b')))),
                                                           OpNode(Token(TokenType.OP, 42, '<'),
                                                                  EnvAttNode(Token(TokenType.ENV_ATT, 36, 'c')),
                                                                  EnvAttNode(Token(TokenType.ENV_ATT, 44, '_c')))),
                                                OpNode(Token(TokenType.OP, 60, '<='),
                                                       EnvAttNode(Token(TokenType.ENV_ATT, 54, 'd')),
                                                       EnvAttNode(Token(TokenType.ENV_ATT, 63, '_d')))),
                                     OpNode(Token(TokenType.OP, 79, '>='),
                                            EnvAttNode(Token(TokenType.ENV_ATT, 73, 'e')),
                                            EnvAttNode(Token(TokenType.ENV_ATT, 82, '_e')))),
                          OpNode(Token(TokenType.OP, 98, '!='),
                                 EnvAttNode(Token(TokenType.ENV_ATT, 92, 'f')),
                                 EnvAttNode(Token(TokenType.ENV_ATT, 101, '_f'))))

        p3 = 'env.1 IN {1,2,3} AND env.2 IN env._2 AND env.3 SUBSET {1,2,3} AND env.3 SUBSET env._3'
        ast3 = BoolOpNode(Token(TokenType.BOOL_OP, 62, 'AND'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 37, 'AND'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 17, 'AND'),
                                                OpNode(Token(TokenType.OP, 6, 'IN'),
                                                       EnvAttNode(Token(TokenType.ENV_ATT, 0, '1')),
                                                       SetNode(Token(TokenType.LSET, 9),
                                                               Token(TokenType.RSET, 15), [
                                                                   IntValNode(Token(TokenType.INT, 10, 1)),
                                                                   IntValNode(Token(TokenType.INT, 12, 2)),
                                                                   IntValNode(Token(TokenType.INT, 14, 3))])),
                                                OpNode(Token(TokenType.OP, 27, 'IN'),
                                                       EnvAttNode(Token(TokenType.ENV_ATT, 21, '2')),
                                                       EnvAttNode(Token(TokenType.ENV_ATT, 30, '_2')))),
                                     OpNode(Token(TokenType.OP, 47, 'SUBSET'),
                                            EnvAttNode(Token(TokenType.ENV_ATT, 41, '3')),
                                            SetNode(Token(TokenType.LSET, 54), Token(TokenType.RSET, 60), [
                                                IntValNode(Token(TokenType.INT, 55, 1)),
                                                IntValNode(Token(TokenType.INT, 57, 2)),
                                                IntValNode(Token(TokenType.INT, 59, 3))]))),
                          OpNode(Token(TokenType.OP, 72, 'SUBSET'),
                                 EnvAttNode(Token(TokenType.ENV_ATT, 66, '3')),
                                 EnvAttNode(Token(TokenType.ENV_ATT, 79, '_3'))))

        self._check_using_policy(p1, ast1)
        self._check_using_policy(p2, ast2)
        self._check_using_policy(p3, ast3)

    def test_nums_and_atts(self):
        p1 = 'user.a = 1 AND object.1 = 0 AND connect.a1 = -1 AND admin._ = 0.1 AND env._abc_123_ = -010.00234567890'
        ast1 = BoolOpNode(Token(TokenType.BOOL_OP, 66, 'AND'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 48, 'AND'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 28, 'AND'),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 11, 'AND'),
                                                           OpNode(Token(TokenType.OP, 7, '='),
                                                                  UsrAttNode(Token(TokenType.USR_ATT, 0, 'a')),
                                                                  IntValNode(Token(TokenType.INT, 9, 1))),
                                                           OpNode(Token(TokenType.OP, 24, '='),
                                                                  ObjAttNode(Token(TokenType.OBJ_ATT, 15, '1')),
                                                                  IntValNode(Token(TokenType.INT, 26, 0)))),
                                                OpNode(Token(TokenType.OP, 43, '='),
                                                       ConAttNode(Token(TokenType.CON_ATT, 32, 'a1')),
                                                       IntValNode(Token(TokenType.INT, 45, -1)))),
                                     OpNode(Token(TokenType.OP, 60, '='),
                                            AdmAttNode(Token(TokenType.ADM_ATT, 52, '_')),
                                            FloatValNode(Token(TokenType.FLOAT, 62, 0.1)))),
                          OpNode(Token(TokenType.OP, 84, '='),
                                 EnvAttNode(Token(TokenType.ENV_ATT, 70, '_abc_123_')),
                                 FloatValNode(Token(TokenType.FLOAT, 86, -10.0023456789))))

        p2 = 'env.stringz_1234567890_ABCDEFG = "HELLO WORLD! 1234567890 !@#$%^&*()_+-=[]{}\\|;\':,./<>?`~ abcdzxy"'
        ast2 = OpNode(Token(TokenType.OP, 31, '='),
                      EnvAttNode(Token(TokenType.ENV_ATT, 0, 'stringz_1234567890_ABCDEFG')),
                      StringValNode(Token(TokenType.STRING, 33,
                                          "HELLO WORLD! 1234567890 !@#$%^&*()_+-=[]{}\\|;':,./<>?`~ abcdzxy")))

        p3 = 'admin.00000 = NULL OR user.____ = 9999999 OR connect.aaaaaa = 0.000001 OR env.AAAAA = -0.000001 OR' \
             ' object.99999 = -9999999'
        ast3 = BoolOpNode(Token(TokenType.BOOL_OP, 96, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 71, 'OR'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 42, 'OR'),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 19, 'OR'),
                                                           OpNode(Token(TokenType.OP, 12, '='),
                                                                  AdmAttNode(Token(TokenType.ADM_ATT, 0, '00000')),
                                                                  NullValNode(Token(TokenType.NULL, 14, 'NULL'))),
                                                           OpNode(Token(TokenType.OP, 32, '='),
                                                                  UsrAttNode(Token(TokenType.USR_ATT, 22, '____')),
                                                                  IntValNode(Token(TokenType.INT, 34, 9999999)))),
                                                OpNode(Token(TokenType.OP, 60, '='),
                                                       ConAttNode(Token(TokenType.CON_ATT, 45, 'aaaaaa')),
                                                       FloatValNode(Token(TokenType.FLOAT, 62, 1e-06)))),
                                     OpNode(Token(TokenType.OP, 84, '='),
                                            EnvAttNode(Token(TokenType.ENV_ATT, 74, 'AAAAA')),
                                            FloatValNode(Token(TokenType.FLOAT, 86, -1e-06)))),
                          OpNode(Token(TokenType.OP, 112, '='),
                                 ObjAttNode(Token(TokenType.OBJ_ATT, 99, '99999')),
                                 IntValNode(Token(TokenType.INT, 114, -9999999))))

        self._check_using_policy(p1, ast1)
        self._check_using_policy(p2, ast2)
        self._check_using_policy(p3, ast3)

    def test_simple_parns(self):
        p1 = '( TRUE )'
        ast1 = BoolValNode(Token(TokenType.BOOL, 2, 'TRUE'))

        p2 = '((FALSE))'
        ast2 = BoolValNode(Token(TokenType.BOOL, 2, 'FALSE'))

        p3 = '( ( ( ( ( ( ( ( ( ( UNDEF ))))))))))'
        ast3 = BoolValNode(Token(TokenType.BOOL, 20, 'UNDEF'))

        p4 = 'NOT(TRUE)'
        ast4 = NotNode(Token(TokenType.NOT_OP, 0, 'NOT'),
                       BoolValNode(Token(TokenType.BOOL, 4, 'TRUE')))

        p5 = 'NOT(NOT(FALSE))'
        ast5 = NotNode(Token(TokenType.NOT_OP, 0, 'NOT'),
                       NotNode(Token(TokenType.NOT_OP, 4, 'NOT'),
                               BoolValNode(Token(TokenType.BOOL, 8, 'FALSE'))))

        p6 = 'NOT( ( NOT( ( ( NOT( NOT( ( NOT( ( UNDEF ))))))))))'
        ast6 = NotNode(Token(TokenType.NOT_OP, 0, 'NOT'),
                       NotNode(Token(TokenType.NOT_OP, 7, 'NOT'),
                               NotNode(Token(TokenType.NOT_OP, 16, 'NOT'),
                                       NotNode(Token(TokenType.NOT_OP, 21, 'NOT'),
                                               NotNode(Token(TokenType.NOT_OP, 28, 'NOT'),
                                                       BoolValNode(Token(TokenType.BOOL, 35, 'UNDEF')))))))

        self._check_using_policy(p1, ast1)
        self._check_using_policy(p2, ast2)
        self._check_using_policy(p3, ast3)
        self._check_using_policy(p4, ast4)
        self._check_using_policy(p5, ast5)
        self._check_using_policy(p6, ast6)

    def test_complex_parns(self):
        p1 = '(user.bool OR admin.bool) AND (connect.bool OR env.bool)'
        ast1 = BoolOpNode(Token(TokenType.BOOL_OP, 26, 'AND'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 11, 'OR'),
                                     UsrAttNode(Token(TokenType.USR_ATT, 1, 'bool')),
                                     AdmAttNode(Token(TokenType.ADM_ATT, 14, 'bool'))),
                          BoolOpNode(Token(TokenType.BOOL_OP, 44, 'OR'),
                                     ConAttNode(Token(TokenType.CON_ATT, 31, 'bool')),
                                     EnvAttNode(Token(TokenType.ENV_ATT, 47, 'bool'))))

        p2 = '(user.bool OR admin.bool) AND connect.bool OR env.bool'
        ast2 = BoolOpNode(Token(TokenType.BOOL_OP, 43, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 26, 'AND'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 11, 'OR'),
                                                UsrAttNode(Token(TokenType.USR_ATT, 1, 'bool')),
                                                AdmAttNode(Token(TokenType.ADM_ATT, 14, 'bool'))),
                                     ConAttNode(Token(TokenType.CON_ATT, 30, 'bool'))),
                          EnvAttNode(Token(TokenType.ENV_ATT, 46, 'bool')))

        p3 = 'user.bool OR admin.bool AND (connect.bool OR env.bool)'
        ast3 = BoolOpNode(Token(TokenType.BOOL_OP, 10, 'OR'),
                          UsrAttNode(Token(TokenType.USR_ATT, 0, 'bool')),
                          BoolOpNode(Token(TokenType.BOOL_OP, 24, 'AND'),
                                     AdmAttNode(Token(TokenType.ADM_ATT, 13, 'bool')),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 42, 'OR'),
                                                ConAttNode(Token(TokenType.CON_ATT, 29, 'bool')),
                                                EnvAttNode(Token(TokenType.ENV_ATT, 45, 'bool')))))

        p4 = 'user.bool OR (admin.bool AND connect.bool) OR env.bool'
        ast4 = BoolOpNode(Token(TokenType.BOOL_OP, 43, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 10, 'OR'),
                                     UsrAttNode(Token(TokenType.USR_ATT, 0, 'bool')),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 25, 'AND'),
                                                AdmAttNode(Token(TokenType.ADM_ATT, 14, 'bool')),
                                                ConAttNode(Token(TokenType.CON_ATT, 29, 'bool')))),
                          EnvAttNode(Token(TokenType.ENV_ATT, 46, 'bool')))

        p5 = '(user.bool OR admin.bool AND connect.bool) OR env.bool'
        ast5 = BoolOpNode(Token(TokenType.BOOL_OP, 43, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 11, 'OR'),
                                     UsrAttNode(Token(TokenType.USR_ATT, 1, 'bool')),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 25, 'AND'),
                                                AdmAttNode(Token(TokenType.ADM_ATT, 14, 'bool')),
                                                ConAttNode(Token(TokenType.CON_ATT, 29, 'bool')))),
                          EnvAttNode(Token(TokenType.ENV_ATT, 46, 'bool')))

        p6 = 'user.bool OR (admin.bool AND connect.bool OR env.bool)'
        ast6 = BoolOpNode(Token(TokenType.BOOL_OP, 10, 'OR'),
                          UsrAttNode(Token(TokenType.USR_ATT, 0, 'bool')),
                          BoolOpNode(Token(TokenType.BOOL_OP, 42, 'OR'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 25, 'AND'),
                                                AdmAttNode(Token(TokenType.ADM_ATT, 14, 'bool')),
                                                ConAttNode(Token(TokenType.CON_ATT, 29, 'bool'))),
                                     EnvAttNode(Token(TokenType.ENV_ATT, 45, 'bool'))))

        p7 = '(((((user.bool) OR ((admin.bool)))) AND (((connect.bool) OR (env.bool)))))'
        ast7 = BoolOpNode(Token(TokenType.BOOL_OP, 36, 'AND'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 16, 'OR'),
                                     UsrAttNode(Token(TokenType.USR_ATT, 5, 'bool')),
                                     AdmAttNode(Token(TokenType.ADM_ATT, 21, 'bool'))),
                          BoolOpNode(Token(TokenType.BOOL_OP, 57, 'OR'),
                                     ConAttNode(Token(TokenType.CON_ATT, 43, 'bool')),
                                     EnvAttNode(Token(TokenType.ENV_ATT, 61, 'bool'))))

        p8 = 'user.1 >= 5 AND (user.2 = 3 OR (user.3 = 4 OR (user.4 = 5 OR (user.6 = 7 OR (user.8 = 9 AND ' \
             'object.8 = 5) OR object.6 = 7) AND object.4 = 5) OR object.3 = 4) AND NOT (user.2 = 3)) OR object.1 <= 5'
        ast8 = BoolOpNode(Token(TokenType.BOOL_OP, 180, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 12, 'AND'),
                                     OpNode(Token(TokenType.OP, 7, '>='),
                                            UsrAttNode(Token(TokenType.USR_ATT, 0, '1')),
                                            IntValNode(Token(TokenType.INT, 10, 5))),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 28, 'OR'),
                                                OpNode(Token(TokenType.OP, 24, '='),
                                                       UsrAttNode(Token(TokenType.USR_ATT, 17, '2')),
                                                       IntValNode(Token(TokenType.INT, 26, 3))),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 158, 'AND'),
                                                           BoolOpNode(Token(TokenType.BOOL_OP, 141, 'OR'),
                                                                      BoolOpNode(Token(TokenType.BOOL_OP, 43, 'OR'),
                                                                                 OpNode(Token(TokenType.OP, 39, '='),
                                                                                        UsrAttNode(Token(TokenType.USR_ATT, 32, '3')),
                                                                                        IntValNode(Token(TokenType.INT, 41, 4))),
                                                                                 BoolOpNode(Token(TokenType.BOOL_OP, 58, 'OR'),
                                                                                            OpNode(Token(TokenType.OP, 54, '='),
                                                                                                   UsrAttNode(Token(TokenType.USR_ATT, 47, '4')),
                                                                                                   IntValNode(Token(TokenType.INT, 56, 5))),
                                                                                            BoolOpNode(Token(TokenType.BOOL_OP, 123, 'AND'),
                                                                                                       BoolOpNode(Token(TokenType.BOOL_OP, 106, 'OR'),
                                                                                                                  BoolOpNode(Token(TokenType.BOOL_OP, 73, 'OR'),
                                                                                                                             OpNode(Token(TokenType.OP, 69, '='),
                                                                                                                                    UsrAttNode(Token(TokenType.USR_ATT, 62, '6')),
                                                                                                                                    IntValNode(Token(TokenType.INT, 71, 7))),
                                                                                                                             BoolOpNode(Token(TokenType.BOOL_OP, 88, 'AND'),
                                                                                                                                        OpNode(Token(TokenType.OP, 84, '='),
                                                                                                                                               UsrAttNode(Token(TokenType.USR_ATT, 77, '8')),
                                                                                                                                               IntValNode(Token(TokenType.INT, 86, 9))),
                                                                                                                                        OpNode(Token(TokenType.OP, 101, '='),
                                                                                                                                               ObjAttNode(Token(TokenType.OBJ_ATT, 92, '8')),
                                                                                                                                               IntValNode(Token(TokenType.INT, 103, 5))))),
                                                                                                                  OpNode(Token(TokenType.OP, 118, '='),
                                                                                                                         ObjAttNode(Token(TokenType.OBJ_ATT, 109, '6')),
                                                                                                                         IntValNode(Token(TokenType.INT, 120, 7)))),
                                                                                                       OpNode(Token(TokenType.OP, 136, '='),
                                                                                                              ObjAttNode(Token(TokenType.OBJ_ATT, 127, '4')),
                                                                                                              IntValNode(Token(TokenType.INT, 138, 5)))))),
                                                                      OpNode(Token(TokenType.OP, 153, '='),
                                                                             ObjAttNode(Token(TokenType.OBJ_ATT, 144, '3')),
                                                                             IntValNode(Token(TokenType.INT, 155, 4)))),
                                                           NotNode(Token(TokenType.NOT_OP, 162, 'NOT'),
                                                                   OpNode(Token(TokenType.OP, 174, '='),
                                                                          UsrAttNode(Token(TokenType.USR_ATT, 167, '2')),
                                                                          IntValNode(Token(TokenType.INT, 176, 3))))))),
                          OpNode(Token(TokenType.OP, 192, '<='),
                                 ObjAttNode(Token(TokenType.OBJ_ATT, 183, '1')),
                                 IntValNode(Token(TokenType.INT, 195, 5))))

        p9 = '((((((((((((user.1 >= 5) AND user.2 = 3) OR user.3 = 4) OR user.4 = 5) OR user.6 = 7) OR user.8 = 9) ' \
             'AND object.8 = 5) OR object.6 = 7) AND object.4 = 5) OR object.3 = 4) AND NOT (user.2 = 3)) ' \
             'OR object.1 <= 5)'
        ast9 = BoolOpNode(Token(TokenType.BOOL_OP, 193, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 171, 'AND'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 154, 'OR'),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 136, 'AND'),
                                                           BoolOpNode(Token(TokenType.BOOL_OP, 119, 'OR'),
                                                                      BoolOpNode(Token(TokenType.BOOL_OP, 101, 'AND'),
                                                                                 BoolOpNode(Token(TokenType.BOOL_OP, 86, 'OR'),
                                                                                            BoolOpNode(Token(TokenType.BOOL_OP, 71, 'OR'),
                                                                                                       BoolOpNode(Token(TokenType.BOOL_OP, 56, 'OR'),
                                                                                                                  BoolOpNode(Token(TokenType.BOOL_OP, 41, 'OR'),
                                                                                                                             BoolOpNode(Token(TokenType.BOOL_OP, 25, 'AND'),
                                                                                                                                        OpNode(Token(TokenType.OP, 19, '>='),
                                                                                                                                               UsrAttNode(Token(TokenType.USR_ATT, 12, '1')),
                                                                                                                                               IntValNode(Token(TokenType.INT, 22, 5))),
                                                                                                                                        OpNode(Token(TokenType.OP, 36, '='),
                                                                                                                                               UsrAttNode(Token(TokenType.USR_ATT, 29, '2')),
                                                                                                                                               IntValNode(Token(TokenType.INT, 38, 3)))),
                                                                                                                             OpNode(Token(TokenType.OP, 51, '='),
                                                                                                                                    UsrAttNode(Token(TokenType.USR_ATT, 44, '3')),
                                                                                                                                    IntValNode(Token(TokenType.INT, 53, 4)))),
                                                                                                                  OpNode(Token(TokenType.OP, 66, '='),
                                                                                                                         UsrAttNode(Token(TokenType.USR_ATT, 59, '4')),
                                                                                                                         IntValNode(Token(TokenType.INT, 68, 5)))),
                                                                                                       OpNode(Token(TokenType.OP, 81, '='),
                                                                                                              UsrAttNode(Token(TokenType.USR_ATT, 74, '6')),
                                                                                                              IntValNode(Token(TokenType.INT, 83, 7)))),
                                                                                            OpNode(Token(TokenType.OP, 96, '='),
                                                                                                   UsrAttNode(Token(TokenType.USR_ATT, 89, '8')),
                                                                                                   IntValNode(Token(TokenType.INT, 98, 9)))),
                                                                                 OpNode(Token(TokenType.OP, 114, '='),
                                                                                        ObjAttNode(Token(TokenType.OBJ_ATT, 105, '8')),
                                                                                        IntValNode(Token(TokenType.INT, 116, 5)))),
                                                                      OpNode(Token(TokenType.OP, 131, '='),
                                                                             ObjAttNode(Token(TokenType.OBJ_ATT, 122, '6')),
                                                                             IntValNode(Token(TokenType.INT, 133, 7)))),
                                                           OpNode(Token(TokenType.OP, 149, '='),
                                                                  ObjAttNode(Token(TokenType.OBJ_ATT, 140, '4')),
                                                                  IntValNode(Token(TokenType.INT, 151, 5)))),
                                                OpNode(Token(TokenType.OP, 166, '='),
                                                       ObjAttNode(Token(TokenType.OBJ_ATT, 157, '3')),
                                                       IntValNode(Token(TokenType.INT, 168, 4)))),
                                     NotNode(Token(TokenType.NOT_OP, 175, 'NOT'),
                                             OpNode(Token(TokenType.OP, 187, '='),
                                                    UsrAttNode(Token(TokenType.USR_ATT, 180, '2')),
                                                    IntValNode(Token(TokenType.INT, 189, 3))))),
                          OpNode(Token(TokenType.OP, 205, '<='),
                                 ObjAttNode(Token(TokenType.OBJ_ATT, 196, '1')),
                                 IntValNode(Token(TokenType.INT, 208, 5))))

        p10 = '(user.1 >= 5 AND (user.2 = 3 OR (user.3 = 4 OR (user.4 = 5 OR (user.6 = 7 OR (user.8 = 9 AND ' \
              '(object.8 = 5 OR (object.6 = 7 AND (object.4 = 5 OR (object.3 = 4 AND (NOT (user.2 = 3) OR ' \
              '(object.1 <= 5))))))))))))'
        ast10 = BoolOpNode(Token(TokenType.BOOL_OP, 13, 'AND'),
                           OpNode(Token(TokenType.OP, 8, '>='),
                                  UsrAttNode(Token(TokenType.USR_ATT, 1, '1')),
                                  IntValNode(Token(TokenType.INT, 11, 5))),
                           BoolOpNode(Token(TokenType.BOOL_OP, 29, 'OR'),
                                      OpNode(Token(TokenType.OP, 25, '='),
                                             UsrAttNode(Token(TokenType.USR_ATT, 18, '2')),
                                             IntValNode(Token(TokenType.INT, 27, 3))),
                                      BoolOpNode(Token(TokenType.BOOL_OP, 44, 'OR'),
                                                 OpNode(Token(TokenType.OP, 40, '='),
                                                        UsrAttNode(Token(TokenType.USR_ATT, 33, '3')),
                                                        IntValNode(Token(TokenType.INT, 42, 4))),
                                                 BoolOpNode(Token(TokenType.BOOL_OP, 59, 'OR'),
                                                            OpNode(Token(TokenType.OP, 55, '='),
                                                                   UsrAttNode(Token(TokenType.USR_ATT, 48, '4')),
                                                                   IntValNode(Token(TokenType.INT, 57, 5))),
                                                            BoolOpNode(Token(TokenType.BOOL_OP, 74, 'OR'),
                                                                       OpNode(Token(TokenType.OP, 70, '='),
                                                                              UsrAttNode(Token(TokenType.USR_ATT, 63, '6')),
                                                                              IntValNode(Token(TokenType.INT, 72, 7))),
                                                                       BoolOpNode(Token(TokenType.BOOL_OP, 89, 'AND'),
                                                                                  OpNode(Token(TokenType.OP, 85, '='),
                                                                                         UsrAttNode(Token(TokenType.USR_ATT, 78, '8')),
                                                                                         IntValNode(Token(TokenType.INT, 87, 9))),
                                                                                  BoolOpNode(Token(TokenType.BOOL_OP, 107, 'OR'),
                                                                                             OpNode(Token(TokenType.OP, 103, '='),
                                                                                                    ObjAttNode(Token(TokenType.OBJ_ATT, 94, '8')),
                                                                                                    IntValNode(Token(TokenType.INT, 105, 5))),
                                                                                             BoolOpNode(Token(TokenType.BOOL_OP, 124, 'AND'),
                                                                                                        OpNode(Token(TokenType.OP, 120, '='),
                                                                                                               ObjAttNode(Token(TokenType.OBJ_ATT, 111, '6')),
                                                                                                               IntValNode(Token(TokenType.INT, 122, 7))),
                                                                                                        BoolOpNode(Token(TokenType.BOOL_OP, 142, 'OR'),
                                                                                                                   OpNode(Token(TokenType.OP, 138, '='),
                                                                                                                          ObjAttNode(Token(TokenType.OBJ_ATT, 129, '4')),
                                                                                                                          IntValNode(Token(TokenType.INT, 140, 5))),
                                                                                                                   BoolOpNode(Token(TokenType.BOOL_OP, 159, 'AND'),
                                                                                                                              OpNode(Token(TokenType.OP, 155, '='),
                                                                                                                                     ObjAttNode(Token(TokenType.OBJ_ATT, 146, '3')),
                                                                                                                                     IntValNode(Token(TokenType.INT, 157, 4))),
                                                                                                                              BoolOpNode(Token(TokenType.BOOL_OP, 181, 'OR'),
                                                                                                                                         NotNode(Token(TokenType.NOT_OP, 164, 'NOT'),
                                                                                                                                                 OpNode(Token(TokenType.OP, 176, '='),
                                                                                                                                                        UsrAttNode(Token(TokenType.USR_ATT, 169, '2')),
                                                                                                                                                        IntValNode(Token(TokenType.INT, 178, 3)))),
                                                                                                                                         OpNode(Token(TokenType.OP, 194, '<='),
                                                                                                                                                ObjAttNode(Token(TokenType.OBJ_ATT, 185, '1')),
                                                                                                                                                IntValNode(Token(TokenType.INT, 197, 5))))))))))))))

        self._check_using_policy(p1, ast1)
        self._check_using_policy(p2, ast2)
        self._check_using_policy(p3, ast3)
        self._check_using_policy(p4, ast4)
        self._check_using_policy(p5, ast5)
        self._check_using_policy(p6, ast6)
        self._check_using_policy(p7, ast7)
        self._check_using_policy(p8, ast8)
        self._check_using_policy(p9, ast9)
        self._check_using_policy(p10, ast10)

    def test_bools(self):
        p1 = 'TRUE OR FALSE AND UNDEF or false and true and undef Or True And False aNd Undef'
        ast1 = BoolOpNode(Token(TokenType.BOOL_OP, 52, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 24, 'OR'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 5, 'OR'),
                                                BoolValNode(Token(TokenType.BOOL, 0, 'TRUE')),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 14, 'AND'),
                                                           BoolValNode(Token(TokenType.BOOL, 8, 'FALSE')),
                                                           BoolValNode(Token(TokenType.BOOL, 18, 'UNDEF')))),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 42, 'AND'),
                                                BoolOpNode(Token(TokenType.BOOL_OP, 33, 'AND'),
                                                           BoolValNode(Token(TokenType.BOOL, 27, 'FALSE')),
                                                           BoolValNode(Token(TokenType.BOOL, 37, 'TRUE'))),
                                                BoolValNode(Token(TokenType.BOOL, 46, 'UNDEF')))),
                          BoolOpNode(Token(TokenType.BOOL_OP, 70, 'AND'),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 60, 'AND'),
                                                BoolValNode(Token(TokenType.BOOL, 55, 'TRUE')),
                                                BoolValNode(Token(TokenType.BOOL, 64, 'FALSE'))),
                                     BoolValNode(Token(TokenType.BOOL, 74, 'UNDEF'))))

        p2 = 'NOT TRUE OR NOT FALSE OR NOT UNDEF'
        ast2 = BoolOpNode(Token(TokenType.BOOL_OP, 22, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 9, 'OR'),
                                     NotNode(Token(TokenType.NOT_OP, 0, 'NOT'),
                                             BoolValNode(Token(TokenType.BOOL, 4, 'TRUE'))),
                                     NotNode(Token(TokenType.NOT_OP, 12, 'NOT'),
                                             BoolValNode(Token(TokenType.BOOL, 16, 'FALSE')))),
                          NotNode(Token(TokenType.NOT_OP, 25, 'NOT'),
                                  BoolValNode(Token(TokenType.BOOL, 29, 'UNDEF'))))

        p3 = 'user.bool OR admin.bool AND env.bool OR connect.bool'
        ast3 = BoolOpNode(Token(TokenType.BOOL_OP, 37, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 10, 'OR'),
                                     UsrAttNode(Token(TokenType.USR_ATT, 0, 'bool')),
                                     BoolOpNode(Token(TokenType.BOOL_OP, 24, 'AND'),
                                                AdmAttNode(Token(TokenType.ADM_ATT, 13, 'bool')),
                                                EnvAttNode(Token(TokenType.ENV_ATT, 28, 'bool')))),
                          ConAttNode(Token(TokenType.CON_ATT, 40, 'bool')))

        p4 = 'NOT connect.bool AND NOT user.bool OR NOT admin.bool AND NOT env.bool'
        ast4 = BoolOpNode(Token(TokenType.BOOL_OP, 35, 'OR'),
                          BoolOpNode(Token(TokenType.BOOL_OP, 17, 'AND'),
                                     NotNode(Token(TokenType.NOT_OP, 0, 'NOT'),
                                             ConAttNode(Token(TokenType.CON_ATT, 4, 'bool'))),
                                     NotNode(Token(TokenType.NOT_OP, 21, 'NOT'),
                                             UsrAttNode(Token(TokenType.USR_ATT, 25, 'bool')))),
                          BoolOpNode(Token(TokenType.BOOL_OP, 53, 'AND'),
                                     NotNode(Token(TokenType.NOT_OP, 38, 'NOT'),
                                             AdmAttNode(Token(TokenType.ADM_ATT, 42, 'bool'))),
                                     NotNode(Token(TokenType.NOT_OP, 57, 'NOT'),
                                             EnvAttNode(Token(TokenType.ENV_ATT, 61, 'bool')))))

        self._check_using_policy(p1, ast1)
        self._check_using_policy(p2, ast2)
        self._check_using_policy(p3, ast3)
        self._check_using_policy(p4, ast4)

    def test_sets(self):
        p1 = 'user.all IN {1, 2, 3, "a", "b", "c", 1.1, 1.2, 1.3, NULL, nUlL, null, "Hello World", 1234567890, ' \
             '0987654321.1234567890}'
        ast1 = OpNode(Token(TokenType.OP, 9, 'IN'),
                      UsrAttNode(Token(TokenType.USR_ATT, 0, 'all')),
                      SetNode(Token(TokenType.LSET, 12), Token(TokenType.RSET, 118),
                              [IntValNode(Token(TokenType.INT, 13, 1)),
                               IntValNode(Token(TokenType.INT, 16, 2)),
                               IntValNode(Token(TokenType.INT, 19, 3)),
                               StringValNode(Token(TokenType.STRING, 22, 'a')),
                               StringValNode(Token(TokenType.STRING, 27, 'b')),
                               StringValNode(Token(TokenType.STRING, 32, 'c')),
                               FloatValNode(Token(TokenType.FLOAT, 37, 1.1)),
                               FloatValNode(Token(TokenType.FLOAT, 42, 1.2)),
                               FloatValNode(Token(TokenType.FLOAT, 47, 1.3)),
                               NullValNode(Token(TokenType.NULL, 52, 'NULL')),
                               NullValNode(Token(TokenType.NULL, 58, 'NULL')),
                               NullValNode(Token(TokenType.NULL, 64, 'NULL')),
                               StringValNode(Token(TokenType.STRING, 70, 'Hello World')),
                               IntValNode(Token(TokenType.INT, 85, 1234567890)),
                               FloatValNode(Token(TokenType.FLOAT, 97, 987654321.1234568))]))

        p2 = 'admin.empty_set = {}'
        ast2 = OpNode(Token(TokenType.OP, 16, '='),
                      AdmAttNode(Token(TokenType.ADM_ATT, 0, 'empty_set')),
                      SetNode(Token(TokenType.LSET, 18), Token(TokenType.RSET, 19), []))

        p3 = 'object.size_one_set_num = {1337}'
        ast3 = OpNode(Token(TokenType.OP, 24, '='),
                      ObjAttNode(Token(TokenType.OBJ_ATT, 0, 'size_one_set_num')),
                      SetNode(Token(TokenType.LSET, 26), Token(TokenType.RSET, 31),
                              [IntValNode(Token(TokenType.INT, 27, 1337))]))

        p4 = 'connect.size_one_set_float = {3.14}'
        ast4 = OpNode(Token(TokenType.OP, 27, '='),
                      ConAttNode(Token(TokenType.CON_ATT, 0, 'size_one_set_float')),
                      SetNode(Token(TokenType.LSET, 29), Token(TokenType.RSET, 34),
                              [FloatValNode(Token(TokenType.FLOAT, 30, 3.14))]))

        p5 = '{"one set with string"} != {"two set", "with string"}'
        ast5 = OpNode(Token(TokenType.OP, 24, '!='),
                      SetNode(Token(TokenType.LSET, 0), Token(TokenType.RSET, 22),
                              [StringValNode(Token(TokenType.STRING, 1, 'one set with string'))]),
                      SetNode(Token(TokenType.LSET, 27), Token(TokenType.RSET, 52),
                              [StringValNode(Token(TokenType.STRING, 28, 'two set')),
                               StringValNode(Token(TokenType.STRING, 39, 'with string'))]))

        p6 = '{null} SUBSET env.one_set_null'
        ast6 = OpNode(Token(TokenType.OP, 7, 'SUBSET'),
                      SetNode(Token(TokenType.LSET, 0), Token(TokenType.RSET, 5),
                              [NullValNode(Token(TokenType.NULL, 1, 'NULL'))]),
                      EnvAttNode(Token(TokenType.ENV_ATT, 14, 'one_set_null')))

        self._check_using_policy(p1, ast1)
        self._check_using_policy(p2, ast2)
        self._check_using_policy(p3, ast3)
        self._check_using_policy(p4, ast4)
        self._check_using_policy(p5, ast5)
        self._check_using_policy(p6, ast6)

    def test_hgabac_paper_ex_a(self):
        p = "user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 28, 'OR'),
                         OpNode(Token(TokenType.OP, 8, 'IN'),
                                UsrAttNode(Token(TokenType.USR_ATT, 0, 'id')),
                                SetNode(Token(TokenType.LSET, 11),
                                        Token(TokenType.RSET, 26), [
                                            IntValNode(Token(TokenType.INT, 12, 5)),
                                            IntValNode(Token(TokenType.INT, 15, 72)),
                                            IntValNode(Token(TokenType.INT, 19, 4)),
                                            IntValNode(Token(TokenType.INT, 22, 6)),
                                            IntValNode(Token(TokenType.INT, 25, 4))])),
                         OpNode(Token(TokenType.OP, 39, '='),
                                UsrAttNode(Token(TokenType.USR_ATT, 31, 'id')),
                                ObjAttNode(Token(TokenType.OBJ_ATT, 41, 'owner'))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_ex_b(self):
        p = "object.required_perms SUBSET user.perms AND user.age >= 18"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 40, 'AND'),
                         OpNode(Token(TokenType.OP, 22, 'SUBSET'),
                                ObjAttNode(Token(TokenType.OBJ_ATT, 0, 'required_perms')),
                                UsrAttNode(Token(TokenType.USR_ATT, 29, 'perms'))),
                         OpNode(Token(TokenType.OP, 53, '>='),
                                UsrAttNode(Token(TokenType.USR_ATT, 44, 'age')),
                                IntValNode(Token(TokenType.INT, 56, 18))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_ex_c(self):
        p = "user.admin OR (user.role = \"doctor\" AND user.id != object.patient)"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 11, 'OR'),
                         UsrAttNode(Token(TokenType.USR_ATT, 0, 'admin')),
                         BoolOpNode(Token(TokenType.BOOL_OP, 36, 'AND'),
                                    OpNode(Token(TokenType.OP, 25, '='),
                                           UsrAttNode(Token(TokenType.USR_ATT, 15, 'role')),
                                           StringValNode(Token(TokenType.STRING, 27, 'doctor'))),
                                    OpNode(Token(TokenType.OP, 48, '!='),
                                           UsrAttNode(Token(TokenType.USR_ATT, 40, 'id')),
                                           ObjAttNode(Token(TokenType.OBJ_ATT, 51, 'patient')))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_ex_c_with_parn_inverted(self):
        p = "(user.admin OR user.role = \"doctor\") AND user.id != object.patient"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 37, 'AND'),
                         BoolOpNode(Token(TokenType.BOOL_OP, 12, 'OR'),
                                    UsrAttNode(Token(TokenType.USR_ATT, 1, 'admin')),
                                    OpNode(Token(TokenType.OP, 25, '='),
                                           UsrAttNode(Token(TokenType.USR_ATT, 15, 'role')),
                                           StringValNode(Token(TokenType.STRING, 27, 'doctor')))),
                         OpNode(Token(TokenType.OP, 49, '!='),
                                UsrAttNode(Token(TokenType.USR_ATT, 41, 'id')),
                                ObjAttNode(Token(TokenType.OBJ_ATT, 52, 'patient'))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_case_1(self):
        p = "\"undergrad\" IN user.user_type AND ((object.object_type = \"book\" AND NOT object.restricted) OR " \
                 "(object.object_type = \"course\" AND user.enrolled_in IN object.req_course))"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 30, 'AND'),
                         OpNode(Token(TokenType.OP, 12, 'IN'),
                                StringValNode(Token(TokenType.STRING, 0, 'undergrad')),
                                UsrAttNode(Token(TokenType.USR_ATT, 15, 'user_type'))),
                         BoolOpNode(Token(TokenType.BOOL_OP, 91, 'OR'),
                                    BoolOpNode(Token(TokenType.BOOL_OP, 64, 'AND'),
                                               OpNode(Token(TokenType.OP, 55, '='),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 36, 'object_type')),
                                                      StringValNode(Token(TokenType.STRING, 57, 'book'))),
                                               NotNode(Token(TokenType.NOT_OP, 68, 'NOT'),
                                                       ObjAttNode(Token(TokenType.OBJ_ATT, 72, 'restricted')))),
                                    BoolOpNode(Token(TokenType.BOOL_OP, 125, 'AND'),
                                               OpNode(Token(TokenType.OP, 114, '='),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 95, 'object_type')),
                                                      StringValNode(Token(TokenType.STRING, 116, 'course'))),
                                               OpNode(Token(TokenType.OP, 146, 'IN'),
                                                      UsrAttNode(Token(TokenType.USR_ATT, 129, 'enrolled_in')),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 149, 'req_course'))))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_case_2(self):
        p = "\"grad\" IN user.user_type AND (object.object_type = \"periodical\" OR (object.object_type " \
                 "=\"course\" AND object.req_course IN user.teaching))"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 25, 'AND'),
                         OpNode(Token(TokenType.OP, 7, 'IN'),
                                StringValNode(Token(TokenType.STRING, 0, 'grad')),
                                UsrAttNode(Token(TokenType.USR_ATT, 10, 'user_type'))),
                         BoolOpNode(Token(TokenType.BOOL_OP, 64, 'OR'),
                                    OpNode(Token(TokenType.OP, 49, '='),
                                           ObjAttNode(Token(TokenType.OBJ_ATT, 30, 'object_type')),
                                           StringValNode(Token(TokenType.STRING, 51, 'periodical'))),
                                    BoolOpNode(Token(TokenType.BOOL_OP, 97, 'AND'),
                                               OpNode(Token(TokenType.OP, 87, '='),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 68, 'object_type')),
                                                      StringValNode(Token(TokenType.STRING, 88, 'course'))),
                                               OpNode(Token(TokenType.OP, 119, 'IN'),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 101, 'req_course')),
                                                      UsrAttNode(Token(TokenType.USR_ATT, 122, 'teaching'))))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_case_3(self):
        p = "\"faculty\" IN user.user_type AND(object.object_type IN {\"book\", \"periodical\", \"course\"} OR " \
                 "(object.object_type = \"archive\" AND object.depart IN user.depart))"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 28, 'AND'),
                         OpNode(Token(TokenType.OP, 10, 'IN'),
                                StringValNode(Token(TokenType.STRING, 0, 'faculty')),
                                UsrAttNode(Token(TokenType.USR_ATT, 13, 'user_type'))),
                         BoolOpNode(Token(TokenType.BOOL_OP, 87, 'OR'),
                                    OpNode(Token(TokenType.OP, 51, 'IN'),
                                           ObjAttNode(Token(TokenType.OBJ_ATT, 32, 'object_type')),
                                           SetNode(Token(TokenType.LSET, 54), Token(TokenType.RSET, 85), [
                                               StringValNode(Token(TokenType.STRING, 55, 'book')),
                                               StringValNode(Token(TokenType.STRING, 63, 'periodical')),
                                               StringValNode(Token(TokenType.STRING, 77, 'course'))])),
                                    BoolOpNode(Token(TokenType.BOOL_OP, 122, 'AND'),
                                               OpNode(Token(TokenType.OP, 110, '='),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 91, 'object_type')),
                                                      StringValNode(Token(TokenType.STRING, 112, 'archive'))),
                                               OpNode(Token(TokenType.OP, 140, 'IN'),
                                                      ObjAttNode(Token(TokenType.OBJ_ATT, 126, 'depart')),
                                                      UsrAttNode(Token(TokenType.USR_ATT, 143, 'depart'))))))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_case_4(self):
        p = "\"staff\" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND " \
                 "env.day_of_week IN {2, 3, 4, 5, 6}"
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 87, 'AND'),
                         BoolOpNode(Token(TokenType.BOOL_OP, 56, 'AND'),
                                    BoolOpNode(Token(TokenType.BOOL_OP, 26, 'AND'),
                                               OpNode(Token(TokenType.OP, 8, 'IN'),
                                                      StringValNode(Token(TokenType.STRING, 0, 'staff')),
                                                      UsrAttNode(Token(TokenType.USR_ATT, 11, 'user_type'))),
                                               OpNode(Token(TokenType.OP, 51, '>='),
                                                      EnvAttNode(Token(TokenType.ENV_ATT, 30, 'time_of_day_hour')),
                                                      IntValNode(Token(TokenType.INT, 54, 8)))),
                                    OpNode(Token(TokenType.OP, 81, '<='),
                                           EnvAttNode(Token(TokenType.ENV_ATT, 60, 'time_of_day_hour')),
                                           IntValNode(Token(TokenType.INT, 84, 16)))),
                         OpNode(Token(TokenType.OP, 107, 'IN'),
                                EnvAttNode(Token(TokenType.ENV_ATT, 91, 'day_of_week')),
                                SetNode(Token(TokenType.LSET, 110), Token(TokenType.RSET, 124), [
                                    IntValNode(Token(TokenType.INT, 111, 2)),
                                    IntValNode(Token(TokenType.INT, 114, 3)),
                                    IntValNode(Token(TokenType.INT, 117, 4)),
                                    IntValNode(Token(TokenType.INT, 120, 5)),
                                    IntValNode(Token(TokenType.INT, 123, 6))])))
        self._check_using_policy(p, ast)

    def test_hgabac_paper_case_5(self):
        p = "\"cs_course\" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND " \
                 "object.object_type = \"periodical\""
        ast = BoolOpNode(Token(TokenType.BOOL_OP, 90, 'AND'),
                         BoolOpNode(Token(TokenType.BOOL_OP, 61, 'AND'),
                                    BoolOpNode(Token(TokenType.BOOL_OP, 32, 'AND'),
                                               OpNode(Token(TokenType.OP, 12, 'IN'),
                                                      StringValNode(Token(TokenType.STRING, 0, 'cs_course')),
                                                      UsrAttNode(Token(TokenType.USR_ATT, 15, 'enrolled_in'))),
                                               OpNode(Token(TokenType.OP, 55, '='),
                                                      ConAttNode(Token(TokenType.CON_ATT, 36, 'ip_octet_1')),
                                                      IntValNode(Token(TokenType.INT, 57, 192)))),
                                    OpNode(Token(TokenType.OP, 84, '='),
                                           ConAttNode(Token(TokenType.CON_ATT, 65, 'ip_octet_2')),
                                           IntValNode(Token(TokenType.INT, 86, 168)))),
                         OpNode(Token(TokenType.OP, 113, '='),
                                ObjAttNode(Token(TokenType.OBJ_ATT, 94, 'object_type')),
                                StringValNode(Token(TokenType.STRING, 115, 'periodical'))))
        self._check_using_policy(p, ast)
