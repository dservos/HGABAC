from enum import Enum, unique

from hgpl.lexing import TokenType
from hgpl.ast import UsrAttNode, ObjAttNode, ConAttNode, EnvAttNode, AdmAttNode, AttNode, ASTResult


@unique
class SymbolType(Enum):
    INT = 1
    FLOAT = 2
    STRING = 3
    BOOL = 4
    UNKNOWN = 5
    SET = 6
    CUSTOM = 7

    @staticmethod
    def convert_token_type(token_type):
        return {TokenType.INT: SymbolType.INT,
                TokenType.FLOAT: SymbolType.FLOAT,
                TokenType.BOOL: SymbolType.BOOL,
                TokenType.STRING: SymbolType.STRING,
                TokenType.LSET: SymbolType.SET,
                TokenType.RSET: SymbolType.SET,
                TokenType.NULL: SymbolType.UNKNOWN}.get(token_type)


class Symbol(object):
    def __init__(self, att_name, att_type=None, stype=None, value=None):
        if stype:
            self.type = stype
        else:
            self.type = SymbolType.UNKNOWN

        if att_type:
            self.att_type = att_type
        else:
            self.att_type = TokenType.UNK_ATT

        #if stype == SymbolType.BOOL and isinstance(value, bool):
        #    value = ASTResult.from_bool(value)
        self._value = None
        self.value = value
        self.att_name = att_name.lower()
        self.name = Symbol._att_type_to_policy_var_prefix(att_type) + att_name.lower()

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        if isinstance(value, bool):
            self._value = ASTResult.from_bool(value)
        else:
            self._value = value

    @staticmethod
    def _att_type_to_policy_var_prefix(att_type):
        return {TokenType.USR_ATT: "user.",
                TokenType.OBJ_ATT: "object.",
                TokenType.ENV_ATT: "env.",
                TokenType.ADM_ATT: "admin.",
                TokenType.CON_ATT: "connect.",
                TokenType.UNK_ATT: "unkown."}.get(att_type, "unkown.")

    def check_val_type(self):
        # TODO: Deal with custom types and NULL
        if (isinstance(self.value, (int, float)) and (self.type == SymbolType.INT or self.type == SymbolType.FLOAT)) or \
           (isinstance(self.value, str) and self.type == SymbolType.STRING) or \
           (isinstance(self.value, (set, list)) and self.type == SymbolType.SET) or \
           (isinstance(self.value, ASTResult) and self.type == SymbolType.BOOL):
            return True
        else:
            return False

    @staticmethod
    def att_to_symbol_name(att_node):
        name = ""
        if isinstance(att_node, UsrAttNode):
            name += "user."
        elif isinstance(att_node, ObjAttNode):
            name += "object."
        elif isinstance(att_node, AdmAttNode):
            name += "admin."
        elif isinstance(att_node, ConAttNode):
            name += "connect."
        elif isinstance(att_node, EnvAttNode):
            name += "env."
        elif isinstance(att_node, AttNode):
            name += "unknown."
        else:
            # TODO: Make user defined exception
            raise Exception()
        return name + att_node.token.value

    def __str__(self):
        return "<{}, {}, {}>".format(self.name, self.type.name, self.value)

    def __repr__(self):
        return "Symbol({}, {}, {}, {})".format(repr(self.att_name), repr(self.type), repr(self.att_type),
                                               repr(self.value))

    def __eq__(self, other):
        return self.name == other.name and self.type == other.type

    def __nq__(self, other):
        return not self.__eq__(other)


class SymbolTable(object):
    def __init__(self):
        self._symbols = dict()

    def define(self, symbol):
        if symbol.name.lower() not in self._symbols:
            self._symbols[symbol.name.lower()] = symbol
            return True
        else:
            return False

    def lookup(self, name):
        if isinstance(name, Symbol):
            name = name.name

        return self._symbols.get(name.lower())

    def lookup_type(self, name):
        if isinstance(name, Symbol):
            name = name.name

        s = self._symbols.get(name.lower())
        if s:
            return s.type
        else:
            return None

    def lookup_att_type(self, name):
        if isinstance(name, Symbol):
            name = name.name

        s = self._symbols.get(name.lower())
        if s:
            return s.att_type
        else:
            return None

    def lookup_att_name(self, name):
        if isinstance(name, Symbol):
            name = name.name

        s = self._symbols.get(name.lower())
        if s:
            return s.att_name
        else:
            return None

    def exists(self, name):
        if isinstance(name, Symbol):
            name = name.name
        return name.lower() in self._symbols

    def names(self):
        return self._symbols.keys()

    def symbols(self):
        return self._symbols.values()

    def lookup_value(self, name):
        if isinstance(name, Symbol):
            name = name.name

        s = self._symbols.get(name.lower())
        if s:
            return s.value
        else:
            # TODO: Make user defined exception
            raise Exception()

    def set_value(self, name, value):
        if isinstance(name, Symbol):
            name = name.name

        s = self._symbols.get(name.lower())
        if s:
            s.value = value
        else:
            # TODO: Make user defined exception
            raise Exception()

    def switch_type(self, name, new_type):
        if isinstance(name, Symbol):
            name = name.name

        if name.lower() in self._symbols:
            s = self._symbols.get(name.lower())
            old_type = s.type
            s.type = new_type
        else:
            # TODO: Make user defined exception
            raise Exception()

        return old_type

    def __str__(self):
        string = "Name\t\tSymbol Type\t\tValue\t\tAtt Type\n"
        for s in self._symbols:
                string += s.name.lower() + "\t\t" + s.type.name + "\t\t" + str(s.value) + "\t\t" + s.att_type.name + \
                          "\n"

        return string

    def __repr__(self):
        return "SymbolTable: <{}>".format(repr(self._symbols))


class SymbolTableBuilder(object):
    def __init__(self, types=None, user_atts=None, env_atts=None, object_atts=None, admin_atts=None, connect_atts=None):
        if types:
            self.types = types
        else:
            self.types = dict()

        if user_atts:
            self.user_atts = user_atts
        else:
            self.user_atts = dict()

        if env_atts:
            self.env_atts = env_atts
        else:
            self.env_atts = dict()

        if object_atts:
            self.object_atts = object_atts
        else:
            self.object_atts = dict()

        if admin_atts:
            self.admin_atts = admin_atts
        else:
            self.admin_atts = dict()

        if connect_atts:
            self.connect_atts = connect_atts
        else:
            self.connect_atts = dict()

    @staticmethod
    def _to_att_type_name(full_att_name):
        return full_att_name.split('.',1)[0]

    @staticmethod
    def _to_att_name(full_att_name):
        return full_att_name.split('.', 1)[1]

    def reset_values(self):
        del self.user_atts
        del self.object_atts
        del self.env_atts
        del self.admin_atts
        del self.connect_atts
        self.user_atts = dict()
        self.object_atts = dict()
        self.env_atts = dict()
        self.admin_atts = dict()
        self.connect_atts = dict()

    def load_mixed_att_val_dict(self, mixed_att_vals):
        x = {"user": self.user_atts, "object": self.object_atts, "env": self.env_atts,
             "admin": self.admin_atts, "connect": self.connect_atts}

        for full_att_name in mixed_att_vals:
            att_dict = x.get(SymbolTableBuilder._to_att_type_name(full_att_name))
            if att_dict is not None:
                att_dict[SymbolTableBuilder._to_att_name(full_att_name)] = mixed_att_vals.get(full_att_name)
            else:
                # TODO: Make user defined
                raise Exception()

    def build(self):
        st = SymbolTable()
        x = {TokenType.USR_ATT:self.user_atts, TokenType.OBJ_ATT:self.object_atts, TokenType.ENV_ATT:self.env_atts,
             TokenType.ADM_ATT:self.admin_atts, TokenType.CON_ATT:self.connect_atts}
        for att_type in x:
            att_dict = x.get(att_type)
            for att_name in att_dict:
                s = Symbol(att_name, att_type, None, att_dict.get(att_name))
                s.type = self.types.get(s.name, SymbolType.UNKNOWN)
                st.define(s)
        return st
