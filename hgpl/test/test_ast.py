from unittest import TestCase

from hgpl.lexing import Lexer
from hgpl.parsing import Parser
from hgpl.ast import ASTEncoder


class TestASTEncoder(TestCase):
    @staticmethod
    def _make_ast(policy_text):
        lex = Lexer(policy_text)
        p = Parser(lex)
        ast = p.parse()
        return ast

    def _encode_decode_test(self, policy_text):
        ast = TestASTEncoder._make_ast(policy_text)
        encoded_bytes = ASTEncoder.encode(ast, False)
        encoded_b64 = ASTEncoder.encode(ast, True)
        decoded_bytes = ASTEncoder.decode(encoded_bytes, False)
        decoded_b64 = ASTEncoder.decode(encoded_b64, True)
        self.assertEqual(ast, decoded_bytes)
        self.assertEqual(ast, decoded_b64)

    def test_benchmark(self):
        setup = '''
from test_ast import TestASTEncoder
from ast import ASTEncoder, ASTNode
import pickle

ps = ['user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner',
      'object.required_perms SUBSET user.perms AND user.age >= 18',
      'user.admin OR (user.role = "doctor" AND user.id != object.patient)',
      '(user.admin OR user.role = "doctor") AND user.id != object.patient',
      '"undergrad" IN user.user_type AND ((object.object_type = "book" AND NOT '
      'object.restricted) OR (object.object_type = "course" AND user.enrolled_in IN '
      'object.req_course))',
      '"grad" IN user.user_type AND (object.object_type = "periodical" OR (object.object_type '
      '="course" AND object.req_course IN user.teaching))',
      '"faculty" IN user.user_type AND(object.object_type IN {"book", "periodical", "course"} OR '
      '(object.object_type = "archive" AND object.depart IN user.depart))',
      '"staff" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND '
      'env.day_of_week IN {2, 3, 4, 5, 6}',
      '"cs_course" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND '
      'object.object_type = "periodical"']
encoded_bytes = []
encoded_b64 = []
pickled = []

for p in ps:
    ASTNode._last_id = -1
    ast = TestASTEncoder._make_ast(p)
    encoded_bytes.append(ASTEncoder.encode(ast, False))
    encoded_b64.append(ASTEncoder.encode(ast, True))
    pickled.append(pickle.dumps(ast, pickle.HIGHEST_PROTOCOL))
        '''

        ps = ["user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner",
              "object.required_perms SUBSET user.perms AND user.age >= 18",
              "user.admin OR (user.role = \"doctor\" AND user.id != object.patient)",
              "(user.admin OR user.role = \"doctor\") AND user.id != object.patient",
              "\"undergrad\" IN user.user_type AND ((object.object_type = \"book\" AND NOT "
              "object.restricted) OR (object.object_type = \"course\" AND user.enrolled_in IN "
              "object.req_course))",
              "\"grad\" IN user.user_type AND (object.object_type = \"periodical\" OR (object.object_type "
              "=\"course\" AND object.req_course IN user.teaching))",
              "\"faculty\" IN user.user_type AND(object.object_type IN {\"book\", \"periodical\", \"course\"} OR "
              "(object.object_type = \"archive\" AND object.depart IN user.depart))",
              "\"staff\" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND "
              "env.day_of_week IN {2, 3, 4, 5, 6}",
              "\"cs_course\" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND "
              "object.object_type = \"periodical\""]

        num_nodes = []
        ast_time = []
        bytes_time = []
        b64_time = []
        pickle_time = []

        for p in ps:
            ast = TestASTEncoder._make_ast(p)
            num_nodes.append(ast.calc_num_nodes())

        num = 100000

        encoded_bytes = []
        encoded_b64 = []

        import pickle
        import json

        print("Num Nodes\tString Size\tBytes Size\tBase64 Bytes Size\tPickle Size")
        for p in ps:
            #ASTNode._last_id = -1
            ast = TestASTEncoder._make_ast(p)
            ps = len(p)
            bs = len(ASTEncoder.encode(ast, False))
            b64s = len(ASTEncoder.encode(ast, True))
            pks = len(pickle.dumps(ast, pickle.HIGHEST_PROTOCOL))
            print(str(ast.calc_num_nodes()) + "\t" + str(ps) + "\t" + str(bs) + "\t" + str(b64s) + "\t" + str(pks))

        #print('Num Nodes\tAST Time\tPure Bytes\tBase64 Bytes')

        #for i in range(0, len(ps)):
            #pickle_time.append(timeit.timeit('pickle.loads(pickled[' + str(i) + '])', setup=setup, number=num))
            #ast_time.append(timeit.timeit('TestASTEncoder._make_ast(ps[' + str(i) + '])', setup=setup, number=num))
            #bytes_time.append(timeit.timeit('ASTEncoder.decode(encoded_bytes[' + str(i) + '], False)', setup=setup, number=num))
            #b64_time.append(timeit.timeit('ASTEncoder.decode(encoded_b64[' + str(i) + '], True)', setup=setup, number=num))
            #print(str(num_nodes[i]) + '\t' + str(ast_time[i]) + '\t' + str(bytes_time[i]) + '\t' + str(b64_time[i]))
            #print(pickle_time[i])

    # TODO: More testing of the Encoder

    def test_enocde_decode_hgabac_paper_ex_a(self):
        self._encode_decode_test("user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner")

    def test_enocde_decode_hgabac_paper_ex_b(self):
        self._encode_decode_test("object.required_perms SUBSET user.perms AND user.age >= 18")

    def test_enocde_decode_hgabac_paper_ex_c(self):
        self._encode_decode_test("user.admin OR (user.role = \"doctor\" AND user.id != object.patient)")

    def test_enocde_decode_hgabac_paper_ex_c_with_parn_inverted(self):
        self._encode_decode_test("(user.admin OR user.role = \"doctor\") AND user.id != object.patient")

    def test_enocde_decode_hgabac_paper_case_1(self):
        self._encode_decode_test("\"undergrad\" IN user.user_type AND ((object.object_type = \"book\" AND NOT "
                                 "object.restricted) OR (object.object_type = \"course\" AND user.enrolled_in IN "
                                 "object.req_course))")

    def test_enocde_decode_hgabac_paper_case_2(self):
        self._encode_decode_test(
            "\"grad\" IN user.user_type AND (object.object_type = \"periodical\" OR (object.object_type "
            "=\"course\" AND object.req_course IN user.teaching))")

    def test_enocde_decode_hgabac_paper_case_3(self):
        self._encode_decode_test(
            "\"faculty\" IN user.user_type AND(object.object_type IN {\"book\", \"periodical\", \"course\"} OR "
            "(object.object_type = \"archive\" AND object.depart IN user.depart))")

    def test_enocde_decode_hgabac_paper_case_4(self):
        self._encode_decode_test(
            "\"staff\" IN user.user_type AND env.time_of_day_hour >= 8 AND env.time_of_day_hour <= 16 AND "
            "env.day_of_week IN {2, 3, 4, 5, 6}")

    def test_enocde_decode_hgabac_paper_case_5(self):
        self._encode_decode_test(
            "\"cs_course\" IN user.enrolled_in AND connect.ip_octet_1 = 192 AND connect.ip_octet_2 = 168 AND "
            "object.object_type = \"periodical\"")

# TODO: Make AST unit tests.
