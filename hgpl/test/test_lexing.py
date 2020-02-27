from unittest import TestCase

from hgpl.lexing import *


class TestToken(TestCase):
    def test_init(self):
        t1 = Token(TokenType.FLOAT, 123, -987.234)
        t2 = Token(TokenType.STRING, 0, "THIS is a TEST!")
        t3 = Token(TokenType.START)
        t4 = Token(TokenType.OP, 1337, ">=")
        t5 = Token(TokenType.INT, 5, 42)
        t6 = Token(TokenType.END, 96)

        self.assertEqual(t1.type, TokenType.FLOAT)
        self.assertEqual(t2.type, TokenType.STRING)
        self.assertEqual(t3.type, TokenType.START)
        self.assertEqual(t4.type, TokenType.OP)
        self.assertEqual(t5.type, TokenType.INT)
        self.assertEqual(t6.type, TokenType.END)

        self.assertEqual(t1.pos, 123)
        self.assertEqual(t2.pos, 0)
        self.assertEqual(t3.pos, -1)
        self.assertEqual(t4.pos, 1337)
        self.assertEqual(t5.pos, 5)
        self.assertEqual(t6.pos, 96)

        self.assertEqual(t1.value, -987.234)
        self.assertEqual(t2.value, "THIS is a TEST!")
        self.assertEqual(t3.value, None)
        self.assertEqual(t4.value, ">=")
        self.assertEqual(t5.value, 42)
        self.assertEqual(t6.value, None)

    def test_eq(self):
        t1 = Token(TokenType.STRING, 123, "ABC")
        t2 = Token(TokenType.STRING, 123, "ABC")
        t3 = Token(TokenType.STRING, 123, "ABC123")
        t4 = Token(TokenType.STRING, 5, "ABC")
        t5 = Token(TokenType.OP, 123, "ABC")
        t6 = Token(TokenType.OP, 5, "ABC123")
        t7 = Token(TokenType.INT, 456, 123)
        t8 = Token(TokenType.INT, 456, 123)
        t9 = Token(TokenType.INT, 456, 321)
        t10 = Token(TokenType.INT, 786, 123)
        t11 = Token(TokenType.FLOAT, 456, 123)

        self.assertEqual(t1, t2)
        self.assertNotEqual(t1, t3)
        self.assertNotEqual(t1, t4)
        self.assertNotEqual(t1, t5)
        self.assertNotEqual(t1, t6)
        self.assertEqual(t7, t8)
        self.assertNotEqual(t7, t1)
        self.assertNotEqual(t7, t9)
        self.assertNotEqual(t7, t10)
        self.assertNotEqual(t7, t11)

    def test_str_and_repr(self):
        # TODO: Make this test for str and repr in TestToken
        pass


class TestLexer(TestCase):
    def test_basic_functions(self):
        policy = "user.age >= 18"
        lex = Lexer(policy)
        correct_list = [Token(TokenType.START, 0)]
        correct_string = "START"
        self.assertEqual(lex.policy(), policy)
        self.assertEqual(lex.current(), Token(TokenType.START, 0))
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)
        token = lex.next()
        correct = Token(TokenType.USR_ATT, 0, "age")
        correct_list.append(correct)
        correct_string += " USR_ATT"
        self.assertEqual(token, correct)
        self.assertEqual(lex.current(), correct)
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)
        token = lex.next()
        correct = Token(TokenType.OP, 9, ">=")
        correct_list.append(correct)
        correct_string += " OP"
        self.assertEqual(token, correct)
        self.assertEqual(lex.current(), correct)
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)
        token = lex.next()
        correct = Token(TokenType.INT, 12, 18)
        correct_list.append(correct)
        correct_string += " INT"
        self.assertEqual(token, correct)
        self.assertEqual(lex.current(), correct)
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)
        token = lex.next()
        correct = Token(TokenType.END, 14)
        correct_list.append(correct)
        correct_string += " END"
        self.assertEqual(token, correct)
        self.assertEqual(lex.current(), correct)
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)
        token = lex.next()
        self.assertEqual(token, None)
        self.assertEqual(lex.current(), correct)
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)
        token = lex.next()
        self.assertEqual(token, None)
        self.assertEqual(lex.current(), correct)
        self.assertEqual(lex.toke_list(), correct_list)
        self.assertEqual(lex.token_string(), correct_string)

    def test_float_errors(self):
        p1 = "123.d23"
        p2 = "123.-89"
        p3 = "00987.(234)"
        p4 = "123.456.789"
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm4:
            lex = Lexer(p4)
            lex.tokenize()
        self.assertEqual(4, cm1.exception.pos)
        self.assertEqual(Token(TokenType.FLOAT, 0), cm1.exception.token)
        self.assertEqual(4, cm2.exception.pos)
        self.assertEqual(Token(TokenType.FLOAT, 0), cm2.exception.token)
        self.assertEqual(6, cm3.exception.pos)
        self.assertEqual(Token(TokenType.FLOAT, 0), cm3.exception.token)
        self.assertEqual(7, cm4.exception.pos)
        self.assertEqual(Token(TokenType.FLOAT, 0), cm4.exception.token)

    def test_int_errors(self):
        p1 = "123abc"
        p2 = "123+123"
        p3 = "098_767"
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        self.assertEqual(3, cm1.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 3, "abc"), cm1.exception.token)
        self.assertEqual(3, cm2.exception.pos)
        self.assertEqual(None, cm2.exception.token)
        self.assertEqual(3, cm3.exception.pos)
        self.assertEqual(None, cm3.exception.token)

    def test_string_errors(self):
        p1 = '"Hello World!'
        p2 = '"My name is \"Dan\"."'
        p3 = '"The following is invalid: ' + chr(31) + '"'
        p4 = '"The following is invalid: ' + chr(127) + '"'
        p5 = '"You can not put a \" in quotes"'
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm4:
            lex = Lexer(p4)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm5:
            lex = Lexer(p5)
            lex.tokenize()
        self.assertEqual(0, cm1.exception.pos)
        self.assertEqual(Token(TokenType.STRING, 0), cm1.exception.token)
        self.assertEqual(13, cm2.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 13, "Dan"), cm2.exception.token)
        self.assertEqual(27, cm3.exception.pos)
        self.assertEqual(Token(TokenType.STRING, 0), cm3.exception.token)
        self.assertEqual(27, cm4.exception.pos)
        self.assertEqual(Token(TokenType.STRING, 0), cm4.exception.token)
        self.assertEqual(24, cm5.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 24, "quotes"), cm5.exception.token)

    def test_not_eq_errors(self):
        p1 = "5 ! = 10"
        p2 = "5 !eq 10"
        p3 = "!(5 = 10)"
        p4 = "!5=10"
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm4:
            lex = Lexer(p4)
            lex.tokenize()
        self.assertEqual(3, cm1.exception.pos)
        self.assertEqual(Token(TokenType.OP, 2, "!="), cm1.exception.token)
        self.assertEqual(3, cm2.exception.pos)
        self.assertEqual(Token(TokenType.OP, 2, "!="), cm2.exception.token)
        self.assertEqual(1, cm3.exception.pos)
        self.assertEqual(Token(TokenType.OP, 0, "!="), cm3.exception.token)
        self.assertEqual(1, cm4.exception.pos)
        self.assertEqual(Token(TokenType.OP, 0, "!="), cm4.exception.token)

    def test_att_errors(self):
        p1 = "myatt.age >= 18"
        p2 = "admin.age = Users.age"
        p3 = "_uSeR.age >= 18"
        p4 = "catage >= 3"
        p5 = "user.-123 = 123"
        p6 = "Admin.+age >= 18"
        p7 = "coNNect.(age) >= 18"
        p8 = 'env."age" >= 18'
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm4:
            lex = Lexer(p4)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm5:
            lex = Lexer(p5)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm6:
            lex = Lexer(p6)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm7:
            lex = Lexer(p7)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm8:
            lex = Lexer(p8)
            lex.tokenize()
        self.assertEqual(0, cm1.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ATT, 0, "myatt"), cm1.exception.token)
        self.assertEqual(12, cm2.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ATT, 12, "users"), cm2.exception.token)
        self.assertEqual(0, cm3.exception.pos)
        self.assertEqual(None, cm3.exception.token)
        self.assertEqual(0, cm4.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 0, "catage"), cm4.exception.token)
        self.assertEqual(5, cm5.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ATT, 0, "user"), cm5.exception.token)
        self.assertEqual(6, cm6.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ATT, 0, "admin"), cm6.exception.token)
        self.assertEqual(8, cm7.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ATT, 0, "connect"), cm7.exception.token)
        self.assertEqual(4, cm8.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ATT, 0, "env"), cm8.exception.token)

    def test_id_errors(self):
        p1 = 'hello_world = "Hello World!"'
        p2 = "5 NOR 6"
        p3 = "dAniEl wAs hERe"
        p4 = "myageis30 = 30"
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm4:
            lex = Lexer(p4)
            lex.tokenize()
        self.assertEqual(0, cm1.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 0, "hello_world"), cm1.exception.token)
        self.assertEqual(2, cm2.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 2, "NOR"), cm2.exception.token)
        self.assertEqual(0, cm3.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 0, "dAniEl"), cm3.exception.token)
        self.assertEqual(0, cm4.exception.pos)
        self.assertEqual(Token(TokenType.UNK_ID, 0, "myageis30"), cm4.exception.token)

    def test_unexpected_char_errors(self):
        p1 = "user.name = 'Daniel Servos'"
        p2 = "user.age += 10"
        p3 = "[1, 2, 3]"
        p4 = "--user.age"
        with self.assertRaises(LexerError) as cm1:
            lex = Lexer(p1)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm2:
            lex = Lexer(p2)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm3:
            lex = Lexer(p3)
            lex.tokenize()
        with self.assertRaises(LexerError) as cm4:
            lex = Lexer(p4)
            lex.tokenize()
        self.assertEqual(12, cm1.exception.pos)
        self.assertEqual(None, cm1.exception.token)
        self.assertEqual(9, cm2.exception.pos)
        self.assertEqual(None, cm2.exception.token)
        self.assertEqual(0, cm3.exception.pos)
        self.assertEqual(None, cm3.exception.token)
        self.assertEqual(0, cm4.exception.pos)
        self.assertEqual(None, cm4.exception.token)

    def _check_policy(self, policy_text, correct_tokens, correct_string):
        lex1 = Lexer(policy_text)
        lex1.tokenize()
        self.assertEqual(correct_tokens, lex1.toke_list())
        self.assertEqual(correct_string, lex1.token_string())
        del lex1

        lex2 = Lexer(policy_text)
        token = lex2.current()
        i = 0
        while token:
            self.assertEqual(correct_tokens[i], token)
            i += 1
            token = lex2.next()
        del lex2

    def test_empty_policies(self):
        policy = ""
        correct_string = "START END"
        correct = [Token(TokenType.START, 0), Token(TokenType.END, 0)]
        self._check_policy(policy, correct, correct_string)
        policy = " "
        correct = [Token(TokenType.START, 0), Token(TokenType.END, 1)]
        self._check_policy(policy, correct, correct_string)
        policy = "          "
        correct = [Token(TokenType.START, 0), Token(TokenType.END, 10)]
        self._check_policy(policy, correct, correct_string)

    def test_ops(self):
        policy = "subset>in<IN=>=<=!=SUBSET"
        correct_string = "START OP OP OP OP OP OP OP OP OP OP END"
        correct = [Token(TokenType.START, 0), Token(TokenType.OP, 0, 'SUBSET'), Token(TokenType.OP, 6, '>'),
                   Token(TokenType.OP, 7, 'IN'), Token(TokenType.OP, 9, '<'), Token(TokenType.OP, 10, 'IN'),
                   Token(TokenType.OP, 12, '='), Token(TokenType.OP, 13, '>='), Token(TokenType.OP, 15, '<='),
                   Token(TokenType.OP, 17, '!='), Token(TokenType.OP, 19, 'SUBSET'), Token(TokenType.END, 25)]
        self._check_policy(policy, correct, correct_string)

    def test_bool_ops_and_null(self):
        policy = "NOT AND OR NULL not and or null Not And Or Null"
        correct_string = "START NOT_OP BOOL_OP BOOL_OP NULL NOT_OP BOOL_OP BOOL_OP NULL NOT_OP BOOL_OP BOOL_OP " \
                         "NULL END"
        correct = [Token(TokenType.START, 0), Token(TokenType.NOT_OP, 0, 'NOT'), Token(TokenType.BOOL_OP, 4, 'AND'),
                   Token(TokenType.BOOL_OP, 8, 'OR'), Token(TokenType.NULL, 11, 'NULL'),
                   Token(TokenType.NOT_OP, 16, 'NOT'), Token(TokenType.BOOL_OP, 20, 'AND'),
                   Token(TokenType.BOOL_OP, 24, 'OR'), Token(TokenType.NULL, 27, 'NULL'),
                   Token(TokenType.NOT_OP, 32, 'NOT'), Token(TokenType.BOOL_OP, 36, 'AND'),
                   Token(TokenType.BOOL_OP, 40, 'OR'), Token(TokenType.NULL, 43, 'NULL'), Token(TokenType.END, 47)]
        self._check_policy(policy, correct, correct_string)

    def test_bool_vals(self):
        policy = "TRUE FALSE UNDEF false true undef fAlSe True uNdeF"
        correct_string = "START BOOL BOOL BOOL BOOL BOOL BOOL BOOL BOOL BOOL END"
        correct = [Token(TokenType.START, 0), Token(TokenType.BOOL, 0, 'TRUE'), Token(TokenType.BOOL, 5, 'FALSE'),
                   Token(TokenType.BOOL, 11, 'UNDEF'), Token(TokenType.BOOL, 17, 'FALSE'),
                   Token(TokenType.BOOL, 23, 'TRUE'), Token(TokenType.BOOL, 28, 'UNDEF'),
                   Token(TokenType.BOOL, 34, 'FALSE'), Token(TokenType.BOOL, 40, 'TRUE'),
                   Token(TokenType.BOOL, 45, 'UNDEF'), Token(TokenType.END, 50)]
        self._check_policy(policy, correct, correct_string)

    def test_int_vals(self):
        policy = "1 2 3 4 5 6 7 8 9 0 -1 -2 -3 -4 -5 -6 -7 -8 -9 -0 12345 -567890 1234567890 0987654321 -0001234" \
                 " 0001234 123-324"
        correct_string = "START INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT INT" \
                         " INT INT INT INT INT INT INT END"
        correct = [Token(TokenType.START, 0), Token(TokenType.INT, 0, 1), Token(TokenType.INT, 2, 2),
                   Token(TokenType.INT, 4, 3), Token(TokenType.INT, 6, 4), Token(TokenType.INT, 8, 5),
                   Token(TokenType.INT, 10, 6), Token(TokenType.INT, 12, 7), Token(TokenType.INT, 14, 8),
                   Token(TokenType.INT, 16, 9), Token(TokenType.INT, 18, 0), Token(TokenType.INT, 20, -1),
                   Token(TokenType.INT, 23, -2), Token(TokenType.INT, 26, -3), Token(TokenType.INT, 29, -4),
                   Token(TokenType.INT, 32, -5), Token(TokenType.INT, 35, -6), Token(TokenType.INT, 38, -7),
                   Token(TokenType.INT, 41, -8), Token(TokenType.INT, 44, -9), Token(TokenType.INT, 47, 0),
                   Token(TokenType.INT, 50, 12345), Token(TokenType.INT, 56, -567890),
                   Token(TokenType.INT, 64, 1234567890), Token(TokenType.INT, 75, 987654321),
                   Token(TokenType.INT, 86, -1234), Token(TokenType.INT, 95, 1234), Token(TokenType.INT, 103, 123),
                   Token(TokenType.INT, 106, -324), Token(TokenType.END, 110)]
        self._check_policy(policy, correct, correct_string)

    def test_float_vals(self):
        policy = "1.1 2.2 3.3 4.4 5.5 6.6 7.7 8.8 9.9 0.1 -1.9 -2.8 -3.7 -4.6 -5.5 -6.4 -7.3 -8.2 -9.1 -0.1 0.0" \
                 " -0.0 134.456 -789.987 1234567890.0987654321 -0987654321.1234567890 00100.00100 -00200.00200 0.123" \
                 " 000.123 123.0 123.000"
        correct_string = "START FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT " \
                         "FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT FLOAT " \
                         "FLOAT FLOAT FLOAT END"
        correct = [Token(TokenType.START, 0), Token(TokenType.FLOAT, 0, 1.1), Token(TokenType.FLOAT, 4, 2.2),
                   Token(TokenType.FLOAT, 8, 3.3), Token(TokenType.FLOAT, 12, 4.4), Token(TokenType.FLOAT, 16, 5.5),
                   Token(TokenType.FLOAT, 20, 6.6), Token(TokenType.FLOAT, 24, 7.7), Token(TokenType.FLOAT, 28, 8.8),
                   Token(TokenType.FLOAT, 32, 9.9), Token(TokenType.FLOAT, 36, 0.1), Token(TokenType.FLOAT, 40, -1.9),
                   Token(TokenType.FLOAT, 45, -2.8), Token(TokenType.FLOAT, 50, -3.7), Token(TokenType.FLOAT, 55, -4.6),
                   Token(TokenType.FLOAT, 60, -5.5), Token(TokenType.FLOAT, 65, -6.4), Token(TokenType.FLOAT, 70, -7.3),
                   Token(TokenType.FLOAT, 75, -8.2), Token(TokenType.FLOAT, 80, -9.1), Token(TokenType.FLOAT, 85, -0.1),
                   Token(TokenType.FLOAT, 90, 0), Token(TokenType.FLOAT, 94, 0), Token(TokenType.FLOAT, 99, 134.456),
                   Token(TokenType.FLOAT, 107, -789.987), Token(TokenType.FLOAT, 116, 1234567890.0987654321),
                   Token(TokenType.FLOAT, 138, -987654321.1234567890), Token(TokenType.FLOAT, 161, 100.001),
                   Token(TokenType.FLOAT, 173, -200.002), Token(TokenType.FLOAT, 186, 0.123),
                   Token(TokenType.FLOAT, 192, 0.123), Token(TokenType.FLOAT, 200, 123.0),
                   Token(TokenType.FLOAT, 206, 123.0), Token(TokenType.END, 213)]
        self._check_policy(policy, correct, correct_string)

    def test_string_vals(self):
        policy = '"""a""A""z""Z"" ""!""#$%&\'()*+\'-./""!01ZXY234$567abc89!"":;<=>?@[\]^_`{|}~"' \
                 '"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 ~!@#$%^&*()_+ =-`" "Hello world!"'
        correct_string = "START STRING STRING STRING STRING STRING STRING STRING STRING STRING STRING STRING STRING END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, ""), Token(TokenType.STRING, 2, "a"),
                   Token(TokenType.STRING, 5, "A"), Token(TokenType.STRING, 8, "z"), Token(TokenType.STRING, 11, "Z"),
                   Token(TokenType.STRING, 14, " "), Token(TokenType.STRING, 17, "!"),
                   Token(TokenType.STRING, 20, "#$%&'()*+'-./"), Token(TokenType.STRING, 35, '!01ZXY234$567abc89!'),
                   Token(TokenType.STRING, 56, ':;<=>?@[\]^_`{|}~'),
                   Token(TokenType.STRING, 75, 'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 '
                                               '~!@#$%^&*()_+ =-`'),
                   Token(TokenType.STRING, 160, 'Hello world!'), Token(TokenType.END, 174)]
        self._check_policy(policy, correct, correct_string)

    def test_atts(self):
        policy = "user.a user.Z user.1 user.0 user.9 user._ env.b env.X env.2 env.0 env.9 env._ object.c object.Y " \
                 "object.3 object.0 object.9 object._ admin.d admin.W admin.4 admin.0 admin.9 admin._ connect.e " \
                 "connect.V connect.5 connect.0 connect.9 connect._ " \
                 "user.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_ " \
                 "env._0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ " \
                 "object.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789 " \
                 "admin.ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789abcdefghijklmnopqrstuvwxyz"
        correct_string = "START USR_ATT USR_ATT USR_ATT USR_ATT USR_ATT USR_ATT " \
                         "ENV_ATT ENV_ATT ENV_ATT ENV_ATT ENV_ATT ENV_ATT " \
                         "OBJ_ATT OBJ_ATT OBJ_ATT OBJ_ATT OBJ_ATT OBJ_ATT " \
                         "ADM_ATT ADM_ATT ADM_ATT ADM_ATT ADM_ATT ADM_ATT " \
                         "CON_ATT CON_ATT CON_ATT CON_ATT CON_ATT CON_ATT " \
                         "USR_ATT ENV_ATT OBJ_ATT ADM_ATT END"
        correct = [Token(TokenType.START, 0), Token(TokenType.USR_ATT, 0, 'a'), Token(TokenType.USR_ATT, 7, 'Z'),
                   Token(TokenType.USR_ATT, 14, '1'), Token(TokenType.USR_ATT, 21, '0'),
                   Token(TokenType.USR_ATT, 28, '9'), Token(TokenType.USR_ATT, 35, '_'),
                   Token(TokenType.ENV_ATT, 42, 'b'), Token(TokenType.ENV_ATT, 48, 'X'),
                   Token(TokenType.ENV_ATT, 54, '2'), Token(TokenType.ENV_ATT, 60, '0'),
                   Token(TokenType.ENV_ATT, 66, '9'), Token(TokenType.ENV_ATT, 72, '_'),
                   Token(TokenType.OBJ_ATT, 78, 'c'), Token(TokenType.OBJ_ATT, 87, 'Y'),
                   Token(TokenType.OBJ_ATT, 96, '3'), Token(TokenType.OBJ_ATT, 105, '0'),
                   Token(TokenType.OBJ_ATT, 114, '9'), Token(TokenType.OBJ_ATT, 123, '_'),
                   Token(TokenType.ADM_ATT, 132, 'd'), Token(TokenType.ADM_ATT, 140, 'W'),
                   Token(TokenType.ADM_ATT, 148, '4'), Token(TokenType.ADM_ATT, 156, '0'),
                   Token(TokenType.ADM_ATT, 164, '9'), Token(TokenType.ADM_ATT, 172, '_'),
                   Token(TokenType.CON_ATT, 180, 'e'), Token(TokenType.CON_ATT, 190, 'V'),
                   Token(TokenType.CON_ATT, 200, '5'), Token(TokenType.CON_ATT, 210, '0'),
                   Token(TokenType.CON_ATT, 220, '9'), Token(TokenType.CON_ATT, 230, '_'),
                   Token(TokenType.USR_ATT, 240, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'),
                   Token(TokenType.ENV_ATT, 309, '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'),
                   Token(TokenType.OBJ_ATT, 377, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789'),
                   Token(TokenType.ADM_ATT, 448, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789abcdefghijklmnopqrstuvwxyz'),
                   Token(TokenType.END, 517)]
        self._check_policy(policy, correct, correct_string)

    def test_parn_and_set(self):
        policy = "{},()}),,({"
        correct_string = "START LSET RSET COMMA LPARN RPARN RSET RPARN COMMA COMMA LPARN LSET END"
        correct = [Token(TokenType.START, 0), Token(TokenType.LSET, 0), Token(TokenType.RSET, 1),
                   Token(TokenType.COMMA, 2), Token(TokenType.LPARN, 3), Token(TokenType.RPARN, 4),
                   Token(TokenType.RSET, 5), Token(TokenType.RPARN, 6), Token(TokenType.COMMA, 7),
                   Token(TokenType.COMMA, 8), Token(TokenType.LPARN, 9), Token(TokenType.LSET, 10),
                   Token(TokenType.END, 11)]
        self._check_policy(policy, correct, correct_string)

    def test_mixed_tokens(self):
        policy = '"user.cat AND env._dog <= SUBSET {},,, () TRUE FALSE UNDEF NULL NOT IN >= != = < > AND OR ' \
                 'connect.123 admin.XYZ -123.3425" USER.SUBSET ENV.IN CONNECT.AND ADMIN.OR OBJECT.NOT uSer.NULL ' \
                 'eNv.TRUE coNNect.FALSE oBJect.UNDEF user._AND_OR_NOT_ obJEct._FALSE_TRUE_NULL "AND" "OR" "NULL" ">"' \
                 ' "=" "NOT" "IN" "123" "123.213" "-123.123" "-123" user.user user.admin user.connect user.env ' \
                 'user.object admin._user_ admin._con admin.env_'
        correct_string = "START STRING USR_ATT ENV_ATT CON_ATT ADM_ATT OBJ_ATT USR_ATT ENV_ATT CON_ATT OBJ_ATT " \
                         "USR_ATT OBJ_ATT STRING STRING STRING STRING STRING STRING STRING STRING STRING STRING" \
                         " STRING USR_ATT USR_ATT USR_ATT USR_ATT USR_ATT ADM_ATT ADM_ATT ADM_ATT END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, 'user.cat AND env._dog <= SUBSET {},,, () '
                                                                         'TRUE FALSE UNDEF NULL NOT IN >= != = < > AND '
                                                                         'OR connect.123 admin.XYZ -123.3425'),
                   Token(TokenType.USR_ATT, 123, 'SUBSET'), Token(TokenType.ENV_ATT, 135, 'IN'),
                   Token(TokenType.CON_ATT, 142, 'AND'), Token(TokenType.ADM_ATT, 154, 'OR'),
                   Token(TokenType.OBJ_ATT, 163, 'NOT'), Token(TokenType.USR_ATT, 174, 'NULL'),
                   Token(TokenType.ENV_ATT, 184, 'TRUE'), Token(TokenType.CON_ATT, 193, 'FALSE'),
                   Token(TokenType.OBJ_ATT, 207, 'UNDEF'), Token(TokenType.USR_ATT, 220, '_AND_OR_NOT_'),
                   Token(TokenType.OBJ_ATT, 238, '_FALSE_TRUE_NULL'), Token(TokenType.STRING, 262, 'AND'),
                   Token(TokenType.STRING, 268, 'OR'), Token(TokenType.STRING, 273, 'NULL'),
                   Token(TokenType.STRING, 280, '>'), Token(TokenType.STRING, 284, '='),
                   Token(TokenType.STRING, 288, 'NOT'), Token(TokenType.STRING, 294, 'IN'),
                   Token(TokenType.STRING, 299, '123'), Token(TokenType.STRING, 305, '123.213'),
                   Token(TokenType.STRING, 315, '-123.123'), Token(TokenType.STRING, 326, '-123'),
                   Token(TokenType.USR_ATT, 333, 'user'), Token(TokenType.USR_ATT, 343, 'admin'),
                   Token(TokenType.USR_ATT, 354, 'connect'), Token(TokenType.USR_ATT, 367, 'env'),
                   Token(TokenType.USR_ATT, 376, 'object'), Token(TokenType.ADM_ATT, 388, '_user_'),
                   Token(TokenType.ADM_ATT, 401, '_con'), Token(TokenType.ADM_ATT, 412, 'env_'),
                   Token(TokenType.END, 422)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_ex_a(self):
        policy = "user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner"
        correct = [Token(TokenType.START, 0), Token(TokenType.USR_ATT, 0, 'id'), Token(TokenType.OP, 8, 'IN'),
                   Token(TokenType.LSET, 11), Token(TokenType.INT, 12, 5), Token(TokenType.COMMA, 13),
                   Token(TokenType.INT, 15, 72), Token(TokenType.COMMA, 17), Token(TokenType.INT, 19, 4),
                   Token(TokenType.COMMA, 20), Token(TokenType.INT, 22, 6), Token(TokenType.COMMA, 23),
                   Token(TokenType.INT, 25, 4), Token(TokenType.RSET, 26), Token(TokenType.BOOL_OP, 28, 'OR'),
                   Token(TokenType.USR_ATT, 31, 'id'), Token(TokenType.OP, 39, '='),
                   Token(TokenType.OBJ_ATT, 41, 'owner'), Token(TokenType.END, 53)]
        correct_string = "START USR_ATT OP LSET INT COMMA INT COMMA INT COMMA INT COMMA INT RSET BOOL_OP USR_ATT OP " \
                         "OBJ_ATT END"
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_ex_b(self):
        policy = "object.required_perms SUBSET user.perms AND user.age >= 18"
        correct_string = "START OBJ_ATT OP USR_ATT BOOL_OP USR_ATT OP INT END"
        correct = [Token(TokenType.START, 0), Token(TokenType.OBJ_ATT, 0, 'required_perms'),
                   Token(TokenType.OP, 22, 'SUBSET'), Token(TokenType.USR_ATT, 29, 'perms'),
                   Token(TokenType.BOOL_OP, 40, 'AND'), Token(TokenType.USR_ATT, 44, 'age'),
                   Token(TokenType.OP, 53, '>='), Token(TokenType.INT, 56, 18), Token(TokenType.END, 58)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_ex_c(self):
        policy = "user.admin OR (user.role = \"doctor\" AND user.id != object.patient)"
        correct_string = "START USR_ATT BOOL_OP LPARN USR_ATT OP STRING BOOL_OP USR_ATT OP OBJ_ATT RPARN END"
        correct = [Token(TokenType.START, 0), Token(TokenType.USR_ATT, 0, 'admin'), Token(TokenType.BOOL_OP, 11, 'OR'),
                   Token(TokenType.LPARN, 14), Token(TokenType.USR_ATT, 15, 'role'), Token(TokenType.OP, 25, '='),
                   Token(TokenType.STRING, 27, 'doctor'), Token(TokenType.BOOL_OP, 36, 'AND'),
                   Token(TokenType.USR_ATT, 40, 'id'), Token(TokenType.OP, 48, '!='),
                   Token(TokenType.OBJ_ATT, 51, 'patient'), Token(TokenType.RPARN, 65), Token(TokenType.END, 66)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_case_1(self):
        # TODO: Fix missing ) at end of policy
        policy = "\"undergrad\" IN user.user_type AND ((object.object_type = \"book\" AND NOT object.restricted) OR " \
                 "(object.object_type = \"course\" AND user.enrolled_in IN object.req_course)"
        correct_string = "START STRING OP USR_ATT BOOL_OP LPARN LPARN OBJ_ATT OP STRING BOOL_OP NOT_OP OBJ_ATT RPARN " \
                         "BOOL_OP LPARN OBJ_ATT OP STRING BOOL_OP USR_ATT OP OBJ_ATT RPARN END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, 'undergrad'), Token(TokenType.OP, 12, 'IN'),
                   Token(TokenType.USR_ATT, 15, 'user_type'), Token(TokenType.BOOL_OP, 30, 'AND'),
                   Token(TokenType.LPARN, 34), Token(TokenType.LPARN, 35), Token(TokenType.OBJ_ATT, 36, 'object_type'),
                   Token(TokenType.OP, 55, '='), Token(TokenType.STRING, 57, 'book'),
                   Token(TokenType.BOOL_OP, 64, 'AND'), Token(TokenType.NOT_OP, 68, 'NOT'),
                   Token(TokenType.OBJ_ATT, 72, 'restricted'), Token(TokenType.RPARN, 89),
                   Token(TokenType.BOOL_OP, 91, 'OR'), Token(TokenType.LPARN, 94),
                   Token(TokenType.OBJ_ATT, 95, 'object_type'), Token(TokenType.OP, 114, '='),
                   Token(TokenType.STRING, 116, 'course'), Token(TokenType.BOOL_OP, 125, 'AND'),
                   Token(TokenType.USR_ATT, 129, 'enrolled_in'), Token(TokenType.OP, 146, 'IN'),
                   Token(TokenType.OBJ_ATT, 149, 'req_course'), Token(TokenType.RPARN, 166), Token(TokenType.END, 167)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_case_2(self):
        # TODO: Fix missing ) at end of policy
        policy = "\"grad\" IN user.user_type AND (object.object_type = \"periodical\" OR (object.object_type " \
                 "=\"course\" AND object.req_course IN user.teaching)"
        correct_string = "START STRING OP USR_ATT BOOL_OP LPARN OBJ_ATT OP STRING BOOL_OP LPARN OBJ_ATT OP STRING " \
                         "BOOL_OP OBJ_ATT OP USR_ATT RPARN END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, 'grad'), Token(TokenType.OP, 7, 'IN'),
                   Token(TokenType.USR_ATT, 10, 'user_type'), Token(TokenType.BOOL_OP, 25, 'AND'),
                   Token(TokenType.LPARN, 29), Token(TokenType.OBJ_ATT, 30, 'object_type'),
                   Token(TokenType.OP, 49, '='), Token(TokenType.STRING, 51, 'periodical'),
                   Token(TokenType.BOOL_OP, 64, 'OR'), Token(TokenType.LPARN, 67),
                   Token(TokenType.OBJ_ATT, 68, 'object_type'), Token(TokenType.OP, 87, '='),
                   Token(TokenType.STRING, 88, 'course'), Token(TokenType.BOOL_OP, 97, 'AND'),
                   Token(TokenType.OBJ_ATT, 101, 'req_course'), Token(TokenType.OP, 119, 'IN'),
                   Token(TokenType.USR_ATT, 122, 'teaching'), Token(TokenType.RPARN, 135), Token(TokenType.END, 136)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_case_3(self):
        policy = "\"faculty\" IN user.user_type AND(object.object_type IN {\"book\", \"periodical\", \"course\"} OR " \
                 "(object.object_type = \"archive\" AND object.depart IN user.depart))"
        correct_string = "START STRING OP USR_ATT BOOL_OP LPARN OBJ_ATT OP LSET STRING COMMA STRING COMMA STRING RSET" \
                         " BOOL_OP LPARN OBJ_ATT OP STRING BOOL_OP OBJ_ATT OP USR_ATT RPARN RPARN END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, 'faculty'), Token(TokenType.OP, 10, 'IN'),
                   Token(TokenType.USR_ATT, 13, 'user_type'), Token(TokenType.BOOL_OP, 28, 'AND'),
                   Token(TokenType.LPARN, 31), Token(TokenType.OBJ_ATT, 32, 'object_type'),
                   Token(TokenType.OP, 51, 'IN'), Token(TokenType.LSET, 54), Token(TokenType.STRING, 55, 'book'),
                   Token(TokenType.COMMA, 61), Token(TokenType.STRING, 63, 'periodical'), Token(TokenType.COMMA, 75),
                   Token(TokenType.STRING, 77, 'course'), Token(TokenType.RSET, 85), Token(TokenType.BOOL_OP, 87, 'OR'),
                   Token(TokenType.LPARN, 90), Token(TokenType.OBJ_ATT, 91, 'object_type'),
                   Token(TokenType.OP, 110, '='), Token(TokenType.STRING, 112, 'archive'),
                   Token(TokenType.BOOL_OP, 122, 'AND'), Token(TokenType.OBJ_ATT, 126, 'depart'),
                   Token(TokenType.OP, 140, 'IN'), Token(TokenType.USR_ATT, 143, 'depart'), Token(TokenType.RPARN, 154),
                   Token(TokenType.RPARN, 155), Token(TokenType.END, 156)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_case_4(self):
        policy = "\"staff\" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND " \
                 "env.day_of_week IN {2, 3, 4, 5, 6}"
        correct_string = "START STRING OP USR_ATT BOOL_OP ENV_ATT OP INT BOOL_OP ENV_ATT OP INT BOOL_OP ENV_ATT OP " \
                         "LSET INT COMMA INT COMMA INT COMMA INT COMMA INT RSET END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, 'staff'), Token(TokenType.OP, 8, 'IN'),
                   Token(TokenType.USR_ATT, 11, 'user_type'), Token(TokenType.BOOL_OP, 26, 'AND'),
                   Token(TokenType.ENV_ATT, 30, 'time_of_day_hour'), Token(TokenType.OP, 51, '>='),
                   Token(TokenType.INT, 54, 8), Token(TokenType.BOOL_OP, 56, 'AND'),
                   Token(TokenType.ENV_ATT, 60, 'time_of_day_hour'), Token(TokenType.OP, 81, '<='),
                   Token(TokenType.INT, 84, 16), Token(TokenType.BOOL_OP, 87, 'AND'),
                   Token(TokenType.ENV_ATT, 91, 'day_of_week'), Token(TokenType.OP, 107, 'IN'),
                   Token(TokenType.LSET, 110), Token(TokenType.INT, 111, 2), Token(TokenType.COMMA, 112),
                   Token(TokenType.INT, 114, 3), Token(TokenType.COMMA, 115), Token(TokenType.INT, 117, 4),
                   Token(TokenType.COMMA, 118), Token(TokenType.INT, 120, 5), Token(TokenType.COMMA, 121),
                   Token(TokenType.INT, 123, 6), Token(TokenType.RSET, 124), Token(TokenType.END, 125)]
        self._check_policy(policy, correct, correct_string)

    def test_hgabac_paper_case_5(self):
        policy = "\"cs_course\" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND " \
                 "object.object_type = \"periodical\""
        correct_string = "START STRING OP USR_ATT BOOL_OP CON_ATT OP INT BOOL_OP CON_ATT OP INT BOOL_OP OBJ_ATT OP" \
                         " STRING END"
        correct = [Token(TokenType.START, 0), Token(TokenType.STRING, 0, 'cs_course'), Token(TokenType.OP, 12, 'IN'),
                   Token(TokenType.USR_ATT, 15, 'enrolled_in'), Token(TokenType.BOOL_OP, 32, 'AND'),
                   Token(TokenType.CON_ATT, 36, 'ip_octet_1'), Token(TokenType.OP, 55, '='),
                   Token(TokenType.INT, 57, 192), Token(TokenType.BOOL_OP, 61, 'AND'),
                   Token(TokenType.CON_ATT, 65, 'ip_octet_2'), Token(TokenType.OP, 84, '='),
                   Token(TokenType.INT, 86, 168), Token(TokenType.BOOL_OP, 90, 'AND'),
                   Token(TokenType.OBJ_ATT, 94, 'object_type'), Token(TokenType.OP, 113, '='),
                   Token(TokenType.STRING, 115, 'periodical'), Token(TokenType.END, 127)]
        self._check_policy(policy, correct, correct_string)
