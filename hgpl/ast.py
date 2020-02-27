from enum import IntEnum, Enum, unique
import struct
import base64
import sys

from hgpl.lexing import TokenType, Token


@unique
class ASTResult(Enum):
    TRUE = 1
    FALSE = 2
    UNDEF = 3

    @staticmethod
    def from_bool(bool):
        if bool:
            return ASTResult.TRUE
        else:
            return ASTResult.FALSE

    @staticmethod
    def tri_not(result):
        return result.__not__()

    @staticmethod
    def tri_and(result1, result2):
        return result1.__and__(result2)

    @staticmethod
    def tri_or(result1, result2):
        return result1.__or__(result2)

    @staticmethod
    def tri_eq(result1, result2):
        return result1.__eq__(result2)

    @staticmethod
    def tri_ne(result1, result2):
        return result1.__ne__(result2)

    def __not__(self):
        if self == ASTResult.TRUE:
            return ASTResult.FALSE
        elif self == ASTResult.FALSE:
            return ASTResult.TRUE
        else:
            return ASTResult.UNDEF

    def __and__(self, other):
        if not isinstance(other, ASTResult):
            raise Exception()

        if other == ASTResult.FALSE or self == ASTResult.FALSE:
            return ASTResult.FALSE
        elif other == ASTResult.UNDEF or self == ASTResult.UNDEF:
            return ASTResult.UNDEF
        else:
            return ASTResult.TRUE

    def __or__(self, other):
        if not isinstance(other, ASTResult):
            raise Exception()

        if self == ASTResult.TRUE or other == ASTResult.TRUE:
            return ASTResult.TRUE
        elif self == ASTResult.UNDEF or other == ASTResult.UNDEF:
            return ASTResult.UNDEF
        else:
            return ASTResult.FALSE

    def __eq__(self, other):
        if isinstance(other, ASTResult):
            return self.value == other.value
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __bool__(self):
        return self.truth()

    def truth(self):
        if self == ASTResult.TRUE:
            return True
        else:
            return False

    def __str__(self):
        return self.name

    def __repr__(self):
        return "ASTResult." + self.name


@unique
class ASTNodeType(IntEnum):
    Unknown = 255
    ASTNode = 0
    OpNode = 11
    BoolOpNode = 12
    BoolValNode = 21
    ValNode = 30
    IntValNode = 31
    FloatValNode = 32
    StringValNode = 33
    ASTNullVal = 34
    NullValNode = 35
    SetNode = 41
    NotNode = 13
    AttNode = 50
    UsrAttNode = 51
    ObjAttNode = 52
    AdmAttNode = 53
    ConAttNode = 54
    EnvAttNode = 55


class ASTNode(object):
    # TODO: Make the id specific to the tree, not all AST.
    _last_id = -1

    def __init__(self, token, left=None, right=None):
        self.token = token
        self.result = None
        self.id = ASTNode._last_id = ASTNode._last_id + 1

        if isinstance(left, list) and right is None:
            self._node_list = left
        elif isinstance(left, ASTNode) and isinstance(right, ASTNode):
            self._node_list = [left, right]
        elif isinstance(left, ASTNode) and right is None:
            self._node_list = [left]
        elif left is None and right is None:
            self._node_list = []
        else:
            # TODO: Make user defined exception for this
            raise Exception()

    def left(self):
        if len(self._node_list) >= 1:
            return self._node_list[0]
        else:
            return None

    def right(self):
        if len(self._node_list) >= 2:
            return self._node_list[1]
        else:
            return None

    def tvalue(self):
        return self.token.value

    def ttype(self):
        return self.token.type

    def tpos(self):
        return self.token.pos

    def ntype(self):
        return getattr(ASTNodeType, self.__class__.__name__, ASTNodeType.Unknown)

    def has_left(self):
        return self.left() is not None

    def has_right(self):
        return self.right() is not None

    def num_nodes(self):
        return len(self._node_list)

    def children(self):
        return self._node_list

    @staticmethod
    def _calc_num_nodes(node):
        count = 1
        for n in node._node_list:
            count += ASTNode._calc_num_nodes(n)
        return count

    def calc_num_nodes(self):
        return ASTNode._calc_num_nodes(self)

    @staticmethod
    def _print_tree(node, indent=0):
        output = ' ' * indent + str(node.token.type.name) + ": " + repr(node.tvalue()) + " -> {}\n"\
            .format(node.result)
        for n in node._node_list:
            output += ASTNode._print_tree(n, indent + 3)
        return output

    def __str__(self):
        return ASTNode._print_tree(self)

    def __repr__(self):
        if len(self._node_list) > 2:
            return self.__class__.__name__ + "(" + repr(self.token) + "," + repr(self._node_list) + ")"
        elif self.left() and self.right():
            return self.__class__.__name__ + "(" + repr(self.token) + ", " + repr(self.left()) + ", " \
                   + repr(self.right()) + ")"
        elif self.left():
            return self.__class__.__name__ + "(" + repr(self.token) + ", " + repr(self.left()) + ")"
        elif self.right():
            return self.__class__.__name__ + "(" + repr(self.token) + ", right=" + repr(self.right()) + ")"
        else:
            return self.__class__.__name__ + "(" + repr(self.token) + ")"

    def __eq__(self, other):
        if self.token == other.token and len(self._node_list) == len(other._node_list):
            i = 0
            for n in self._node_list:
                if not n.__eq__(other._node_list[i]):
                    return False
                i += 1
        else:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


class OpNode(ASTNode):
    pass


class BoolOpNode(ASTNode):
    pass


class BoolValNode(ASTNode):
    def __init__(self, token):
        super().__init__(token)
        if self.tvalue().upper() == "TRUE":
            self.result = ASTResult.TRUE
        elif self.tvalue().upper() == "FALSE":
            self.result = ASTResult.FALSE
        else:
            self.result = ASTResult.UNDEF


class ValNode(ASTNode):
    def __init__(self, token):
        super().__init__(token)
        self.result = self.tvalue()


class IntValNode(ValNode):
    pass


class FloatValNode(ValNode):
    pass


class StringValNode(ValNode):
    pass


class ASTNullVal(object):
    def __eq__(self, other):
        return isinstance(other, ASTNullVal)

    def __ne__(self, other):
        return not isinstance(other, ASTNullVal)


class NullValNode(ValNode):
    def __init__(self, token):
        super().__init__(token)
        self.result = ASTNullVal()


class SetNode(ASTNode):
    def __init__(self, start_token, end_token=None, val_nodes=None):
        self.start_token = start_token
        self.end_token = end_token
        super().__init__(start_token, val_nodes)

    #def tvalue(self):
    #    vals = []
    #    for n in self._node_list:
    #        if n.token.type != TokenType.NULL:
    #            vals.append(n.tvalue())
    #        else:
    #            vals.append(None)
    #    return vals

    def __repr__(self):
        return self.__class__.__name__ + "(" + repr(self.start_token) + ", " + repr(self.end_token) + ", " + \
               repr(self._node_list) + ")"


class NotNode(ASTNode):
    def __init__(self, token, left=None):
        super().__init__(token, left)


class AttNode(ASTNode):
    def __init__(self, token):
        super().__init__(token)


class UsrAttNode(AttNode):
    pass


class ObjAttNode(AttNode):
    pass


class AdmAttNode(AttNode):
    pass


class ConAttNode(AttNode):
    pass


class EnvAttNode(AttNode):
    pass


class ASTEncoder(object):
    _version = 1
    _encoding_head = struct.Struct("<BHH")
    _encoding_body_head = struct.Struct("<HBBHHH")

    @staticmethod
    def _encode_node(node):
        if node.ttype() == TokenType.INT:
            tval_format = 'i'
            tval_size = 4
            tval = node.tvalue()
        elif node.ttype() == TokenType.FLOAT:
            tval_format = 'f'
            tval_size = 4
            tval = node.tvalue()
        #elif node.ttype() == TokenType.BOOL:
        #    tval_format = 'B'
        #    tval_size = 1
        #    tval = node.tvalue()
        else:
            if node.tvalue() is None:
                tval_format = ''
                tval_size = 0
                tval = None
            elif isinstance(node.tvalue(), str):
                tval_size = len(node.tvalue())
                tval_format = str(tval_size) + 's'
                tval = bytes(node.tvalue(), 'utf-8')
            else:
                print(node.tvalue())
                print(node.tvalue().__class__.__name__)
                # TODO: Custom exception
                raise Exception()

        node_header = ASTEncoder._encoding_body_head.pack(node.id, node.ntype().value, node.ttype().value, node.tpos(), tval_size,
                                              node.num_nodes())
        if tval_size > 0:
            tvalue = struct.pack('<' + tval_format, tval)
        else:
            tvalue = None

        if node.num_nodes() > 0:
            child_ids = tuple(child.id for child in node._node_list)
            children = struct.pack('<' + str(node.num_nodes()) + 'H', *child_ids)
        else:
            child_ids = None
            children = None

        encoded_node = b''.join((filter(None, (node_header, tvalue, children))))
        encoded_nodes = (encoded_node,)

        del children
        del child_ids
        del tvalue
        del tval_size
        del tval_format
        del node_header

        for n in node.children():
            encoded_nodes += ASTEncoder._encode_node(n)

        return encoded_nodes

    @staticmethod
    def encode(ast, encode_in_base64=False):
        encoded_nodes = ASTEncoder._encode_node(ast)
        header = ASTEncoder._encoding_head.pack(ASTEncoder._version, len(encoded_nodes), ast.id)
        encoded = header + b''.join(encoded_nodes)

        if encode_in_base64:
            return base64.b64encode(encoded)
        else:
            return encoded

    @staticmethod
    def decode(encoded_bytes, encoded_in_base64=False):
        if encoded_in_base64:
            encoded_bytes = base64.b64decode(encoded_bytes)

        version, num_nodes, root_id = ASTEncoder._encoding_head.unpack(encoded_bytes[0:ASTEncoder._encoding_head.size])
        byte_count = ASTEncoder._encoding_head.size

        # TODO: Check version

        nodes = {}

        for i in range(0, num_nodes):
            node_id, node_type, token_type, token_pos, token_val_size, node_num_child = \
                ASTEncoder._encoding_body_head.unpack(encoded_bytes[byte_count:byte_count +
                                                                               ASTEncoder._encoding_body_head.size])
            byte_count += ASTEncoder._encoding_body_head.size

            if token_val_size > 0:
                str_flag = False

                if token_type == TokenType.INT.value:
                    tval_format = 'i'
                elif token_type == TokenType.FLOAT.value:
                    tval_format = 'f'
                #elif token_type == TokenType.BOOL.value:
                #    tval_format = 'B'
                else:
                    str_flag = True
                    tval_format = str(token_val_size) + 's'

                token_val = struct.unpack('<' + tval_format,  encoded_bytes[byte_count:byte_count + token_val_size])[0]

                if str_flag:
                    token_val = token_val.decode('utf-8')

                byte_count += token_val_size
            else:
                token_val = None

            if node_num_child > 0:
                node_children = struct.unpack('<' + str(node_num_child) + 'H', encoded_bytes[byte_count:byte_count + node_num_child * 2])
                byte_count += node_num_child * 2
            else:
                node_children = ()

            token = Token(TokenType(token_type), token_pos, token_val)
            ntype = ASTNodeType(node_type)
            nclass = getattr(sys.modules[__name__], ntype.name)
            node = nclass(token)
            node.id = node_id
            node.children_ids = node_children
            nodes[node.id] = node

        for nid, node in nodes.items():
            for cid in node.children_ids:
                if cid in nodes:
                    node._node_list.append(nodes.get(cid))
                else:
                    # TODO: Custom exception
                    raise Exception()

        if root_id in nodes:
            return nodes.get(root_id)
        else:
            # TODO: Custom exception
            raise Exception()