from tkinter import *
from tkinter import ttk
from copy import deepcopy

from hgpl.symbols import SymbolType, SymbolTableBuilder
from hgpl.lexing import TokenType, Lexer
from hgpl.errors import HGPLError, ErrorType
from hgpl.parsing import Parser
from hgpl.semantics import TypeChecker, TypeCheckerResult
from hgpl.interpreting import Interpreter


class EditAttDialog(object):
    def __init__(self, item_id, att_name, att_val, root, call):
        self.top = Toplevel(root)
        self.att_name = att_name
        self.att_val = att_val
        self.call = call
        self.item_id = item_id
        f = Frame(self.top, borderwidth=4, relief='ridge')
        f.pack(fill=BOTH, expand=True)
        l = Label(f, text="Enter value for " + self.att_name + ": ")
        l.pack(padx=4, pady=4)
        self.entry = Entry(f)
        self.entry.delete(0, END)
        self.entry.insert(0, str(self.att_val))
        self.entry.pack(pady=4)
        b = Button(f, text='Submit', command=self._command_submit)
        b.pack()

    def _command_submit(self):
        self.call(self.item_id, self.entry.get())
        self.top.destroy()


class LexerDemoFrame(Frame):
    def __init__(self, parent, example_policies=None, example_symbol_table=None):
        Frame.__init__(self, parent)
        self.policies = example_policies
        self.symbol_table = example_symbol_table
        self.parent = parent
        self.token_list = None
        self.ast = None
        self.type_check_symbol_table = None
        self.pack(fill=BOTH, expand=True)
        self._build_widgets()

    def _build_token_list(self):
        if hasattr(self, '_token_tree') and self._token_tree is not None:
            self._token_tree.pack_forget()
            del self._token_tree

        self._token_tree = ttk.Treeview(self._output_frame, columns=('value', 'pos'), height=10)
        self._token_tree.grid(row=1, column=0, sticky=(E, W), rowspan=3)
        self._token_tree_scroll = ttk.Scrollbar(self._output_frame, orient=VERTICAL, command=self._token_tree.yview)
        self._token_tree.configure(yscrollcommand=self._token_tree_scroll.set)
        self._token_tree_scroll.grid(row=1, column=1, sticky=(N, S), rowspan=3)

        self._token_tree.column('#0', width=70, anchor='center')
        self._token_tree.heading('#0', text='Type')
        self._token_tree.column('value', width=60, anchor='center')
        self._token_tree.heading('value', text='Value')
        self._token_tree.column('pos', width=60, anchor='center')
        self._token_tree.heading('pos', text='Position')

        if self.token_list is not None and len(self.token_list) > 0:
            for t in self.token_list:
                self._token_tree.insert('', 'end', text=t.type.name, values=(str(t.value), t.pos))

    def _build_symbol_table(self):
        if hasattr(self, '_symbol_tree') and self._symbol_tree is not None:
            self._symbol_tree.pack_forget()
            del self._symbol_tree

        self._symbol_tree = ttk.Treeview(self._output_frame, columns=('type', 'value'), height=10)
        self._symbol_tree.grid(row=1, column=7, sticky=(E, W), rowspan=3)
        self._symbol_tree_scroll = ttk.Scrollbar(self._output_frame, orient=VERTICAL, command=self._symbol_tree.yview)
        self._symbol_tree.configure(yscrollcommand=self._symbol_tree_scroll.set)
        self._symbol_tree_scroll.grid(row=1, column=8, sticky=(N, S), rowspan=3)

        self._symbol_tree.column('#0', width=100, anchor='center')
        self._symbol_tree.heading('#0', text='Name')
        self._symbol_tree.column('type', width=75, anchor='center')
        self._symbol_tree.heading('type', text='Type')
        self._symbol_tree.column('value', width=75, anchor='center')
        self._symbol_tree.heading('value', text='Value')

        if self.type_check_symbol_table is not None:
            for symbol in self.type_check_symbol_table.symbols():
                self._symbol_tree.insert('', 'end', text=symbol.name, values=[symbol.type.name, symbol.value])

    def _insert_ast_nodes(self, parent, node):
        nid = self._ast_tree.insert(parent, 'end', text=node.ttype().name, values=(node.tvalue(), node.result), open=True)
        for child in node.children():
            self._insert_ast_nodes(nid, child)

    def _build_ast(self):
        if hasattr(self, '_ast_tree') and self._ast_tree is not None:
            self._ast_tree.pack_forget()
            del self._ast_tree

        self._ast_tree = ttk.Treeview(self._output_frame, columns=('value', 'result'), height=10)
        self._ast_tree.grid(row=1, column=4, sticky=(E, W), rowspan=3)
        self._ast_tree_scroll = ttk.Scrollbar(self._output_frame, orient=VERTICAL, command=self._ast_tree.yview)
        self._ast_tree.configure(yscrollcommand=self._ast_tree_scroll.set)
        self._ast_tree_scroll.grid(row=1, column=5, sticky=(N, S), rowspan=3)

        self._ast_tree.column('#0', width=150, anchor='center')
        self._ast_tree.heading('#0', text='Token')
        self._ast_tree.column('value', width=105, anchor='center')
        self._ast_tree.heading('value', text='Value')
        self._ast_tree.column('result', width=150, anchor='center')
        self._ast_tree.heading('result', text='Result')

        if self.ast is not None:
            self._insert_ast_nodes('', self.ast)

    def _build_att_tree(self):
        if hasattr(self, '_att_tree') and self._att_tree is not None:
            self._att_tree.pack_forget()
            del self._att_tree

        self._att_tree = ttk.Treeview(self._input_frame, columns=('type','value'), height=10)
        self._usr_tree_node = self._att_tree.insert('', 'end', text='User Attributes')
        self._obj_tree_node = self._att_tree.insert('', 'end', text='Object Attributes')
        self._env_tree_node = self._att_tree.insert('', 'end', text='Environment Attributes')
        self._con_tree_node = self._att_tree.insert('', 'end', text='Connection Attributes')
        self._adm_tree_node = self._att_tree.insert('', 'end', text='Admin Attributes')
        self._att_tree.column('#0', width=225, anchor='center')
        self._att_tree.heading('#0', text='Name')
        self._att_tree.column('type', width=100, anchor='center')
        self._att_tree.heading('type', text='Type')
        self._att_tree.column('value', width=400, anchor='center')
        self._att_tree.heading('value', text='Value')
        self._att_tree.grid(row=1, column=1, pady=5, sticky=(E,W))
        self._att_tree_scroll = ttk.Scrollbar(self._input_frame, orient=VERTICAL, command=self._att_tree.yview)
        self._att_tree.configure(yscrollcommand=self._att_tree_scroll.set)
        self._att_tree_scroll.grid(row=1, column=3, pady=5, sticky=(N,S))

        self._att_tree.bind("<Double-1>", self._on_row_activated)

        for symbol in self.symbol_table.symbols():
            parent_node = {TokenType.USR_ATT: self._usr_tree_node,
                           TokenType.OBJ_ATT: self._obj_tree_node,
                           TokenType.ENV_ATT: self._env_tree_node,
                           TokenType.ADM_ATT: self._adm_tree_node,
                           TokenType.CON_ATT: self._con_tree_node,
                           TokenType.UNK_ATT: ''}.get(symbol.att_type, '')

            self._att_tree.insert(parent_node, 'end', text=symbol.att_name, values=[symbol.type.name, symbol.value])

    def _update_att(self, item_id, value):
        item = self._att_tree.item(item_id)
        parentid = self._att_tree.parent(item_id)
        type = {self._usr_tree_node: 'user.', self._obj_tree_node: 'object.', self._env_tree_node: 'env.',
                self._adm_tree_node: 'admin.', self._con_tree_node: 'connect.'}.get(parentid, '')

        v = None
        try:
            if item['values'][0] == 'INT':
                v = int(value)
            elif item['values'][0] == 'FLOAT':
                v = float(value)
            elif item['values'][0] == 'SET':
                v = {x.strip() for x in value.replace('{', '').replace('}', '').replace('\'', '').split(',')}
            elif item['values'][0] == 'STRING':
                v = str(value)
            elif item['values'][0] == 'BOOL':
                if value.lower().strip() == 'true' or value.lower().strip() == 't' or value.lower().strip() == '1':
                    v = True
                else:
                    v = False
        except ValueError as e:
            print(e)
        else:
            if v is not None:
                self._att_tree.item(item_id, values=(item['values'][0], v))
                self.symbol_table.set_value(type + item['text'], v)

    def _on_row_activated(self, event):
        iid = self._att_tree.selection()[0]
        if iid not in (self._usr_tree_node, self._obj_tree_node, self._env_tree_node, self._con_tree_node, self._adm_tree_node):
            item = self._att_tree.item(iid)
            parentid = self._att_tree.parent(iid)
            type = {self._usr_tree_node: 'user.', self._obj_tree_node: 'object.', self._env_tree_node: 'env.', self._adm_tree_node: 'admin.', self._con_tree_node: 'connect.'}.get(parentid, '')
            EditAttDialog(iid, type + item['text'], item['values'][1], self.parent, self._update_att)

    def _build_widgets(self):
        self._input_frame = Frame(self, relief=RAISED, borderwidth=2)
        self._input_frame.grid(row=0, column=0, sticky=(E,W))

        self._control_frame = Frame(self, relief=RAISED, borderwidth=2)
        self._control_frame.grid(row=0, column=1, sticky=(N,S))

        self._output_frame = Frame(self, relief=RAISED, borderwidth=2)
        self._output_frame.grid(row=1, column=0, columnspan=2, sticky=(E,W))

        self._console_frame = Frame(self, relief=RAISED, borderwidth=2)
        self._console_frame.grid(row=2, column=0, columnspan=2, sticky=(E,W))

        self._policy_label = Label(self._input_frame, text="Policy: ")
        self._policy_label.grid(row=0, column=0)
        self._policy_combo = ttk.Combobox(self._input_frame, width=125)
        self._policy_combo.grid(row=0, column=1)
        self._policy_combo['values'] = self.policies

        self._build_att_tree()
        self._policy_label = Label(self._input_frame, text="Attributes: ")
        self._policy_label.grid(row=1, column=0)

        button_width = 15
        button_height = 2
        button_push_padx = 5
        self._tokenize_button = Button(self._control_frame, text="Tokenize", command=self._command_tokenize, width=button_width, height=button_height)
        self._tokenize_button.pack(padx=button_push_padx, expand=True)
        self._parse_button = Button(self._control_frame, text="Parse", command=self._command_parse, width=button_width, height=button_height, state=DISABLED)
        self._parse_button.pack(padx=button_push_padx, expand=True)
        self._typecheck_button = Button(self._control_frame, text="Type Check", command=self._command_type_check, width=button_width, height=button_height, state=DISABLED)
        self._typecheck_button.pack(padx=button_push_padx, expand=True)
        self._optimize_button = Button(self._control_frame, text="Optimize", command=self._command_optimize, width=button_width, height=button_height, state=DISABLED)
        self._optimize_button.pack(padx=button_push_padx, expand=True)
        self._interpret_button = Button(self._control_frame, text="Interpret", command=self._command_interpret, width=button_width, height=button_height, state=DISABLED)
        self._interpret_button.pack(padx=button_push_padx, expand=True)
        self._reset_button = Button(self._control_frame, text="Reset", command=self._command_reset, width=button_width, height=button_height)
        self._reset_button.pack(padx=button_push_padx, expand=True)

        self._token_label = Label(self._output_frame, text="Token List: ")
        self._token_label.grid(row=0, column=0, sticky=(W,S))
        self._build_token_list()

        Frame(self._output_frame, width=15).grid(row=0,column=3,rowspan=4)

        self._ast_label = Label(self._output_frame, text="Abstract Syntax Tree: ")
        self._ast_label.grid(row=0, column=4, sticky=(W, S))
        self._build_ast()

        Frame(self._output_frame, width=15).grid(row=0, column=6, rowspan=4)

        self._typecheck_label = Label(self._output_frame, text="Typecheck Result: ")
        #self._typecheck_label.grid(row=0, column=7, sticky=(W, S))
        self._typecheck = Entry(self._output_frame, state="readonly", width=40)
        #self._typecheck.grid(row=1, column=7, sticky=(N, W, E))

        self._result_label = Label(self._output_frame, text="Overall Result: ")
        #self._result_label.grid(row=2, column=7, sticky=(W, S))
        self._result = Entry(self._output_frame, state="readonly", width=40)
        #self._result.grid(row=3, column=7, sticky=(N, W, E))

        #Frame(self._output_frame, height=5).grid(row=4, column=0, columnspan=7)

        self._symbol_label = Label(self._output_frame, text="Symbol Table: ")
        self._symbol_label.grid(row=0, column=7, sticky=(W, S))
        self._build_symbol_table()

        self._console = Text(self._console_frame, width=120, height=11, state=DISABLED)
        self._console.grid(row=0, column=0, sticky=(W, E))
        self._console_scroll = ttk.Scrollbar(self._console_frame, orient=VERTICAL, command=self._console.yview)
        self._console.configure(yscrollcommand=self._console_scroll.set)
        self._console_scroll.grid(row=0, column=1, sticky=(N, S))

    def _command_tokenize(self):
        del self.ast
        del self.token_list
        del self.type_check_symbol_table

        self.token_list = None
        self.ast = None
        self.type_check_symbol_table = None
        self._result.delete(0, END)
        self._typecheck.delete(0, END)
        self._build_token_list()
        self._build_ast()
        self._build_symbol_table()
        self._parse_button.config(state=DISABLED)
        self._typecheck_button.config(state=DISABLED)
        self._optimize_button.config(state=DISABLED)
        self._interpret_button.config(state=DISABLED)

        self._policy_combo.config(state=DISABLED)

        self._console.config(state=NORMAL)
        self._console.insert(END, "Running lexical analysis of policy \"" + self._policy_combo.get() + "\"...\n")
        try:
            lex = Lexer(self._policy_combo.get())
            lex.tokenize()
            self.token_list = lex.toke_list()
        except HGPLError as e:
            self._console.insert(END, "ERROR: " + str(e) + "\n\n")
        else:
            self._console.insert(END, "Successfully tokenized policy!\nFound " + str(len(self.token_list)) + " tokens.\n\n")
            self._build_token_list()
            self._parse_button.config(state=NORMAL)
            self._tokenize_button.config(state=DISABLED)
        finally:
            self._console.see(END)
            self._console.config(state=DISABLED)

    def _command_parse(self):
        del self.ast
        del self.type_check_symbol_table

        self.ast = None
        self.type_check_symbol_table = None
        self._result.delete(0, END)
        self._typecheck.delete(0, END)
        self._build_ast()
        self._build_symbol_table()

        self._typecheck_button.config(state=DISABLED)
        self._optimize_button.config(state=DISABLED)
        self._interpret_button.config(state=DISABLED)
        self._tokenize_button.config(state=DISABLED)

        self._console.config(state=NORMAL)
        self._console.insert(END, "Running parser on token list...\n")
        try:
            p = Parser(self.token_list, self._policy_combo.get())
            self.ast = p.parse()
        except HGPLError as e:
            self._console.insert(END, "ERROR: " + str(e) + "\n\n")
        else:
            self._console.insert(END, "Successfully build AST from token list!\n\n")
            self._build_ast()
            self._typecheck_button.config(state=NORMAL)
            self._parse_button.config(state=DISABLED)
        finally:
            self._console.see(END)
            self._console.config(state=DISABLED)

    def _command_type_check(self):
        del self.type_check_symbol_table
        self.type_check_symbol_table = None
        self._build_symbol_table()

        self._result.delete(0, END)
        self._typecheck.delete(0, END)

        self._optimize_button.config(state=DISABLED)
        self._interpret_button.config(state=DISABLED)
        self._tokenize_button.config(state=DISABLED)
        self._parse_button.config(state=DISABLED)

        self._console.config(state=NORMAL)
        self._console.insert(END, "Running type checker and symbol table builder on AST...\n")
        try:
            tc = TypeChecker(self.ast, self._policy_combo.get())
            tc.check()
            errors = tc.get_errors()
            warns = tc.get_warnings()

            if errors:
                self._console.insert(END, "Errors:\n")
                for e in errors:
                    self._console.insert(END,  "  * " + str(e) + "\n")

            if warns:
                self._console.insert(END, "Warnings:\n")
                for w in warns:
                    self._console.insert(END,  "  * " + str(w) + "\n")

            self.type_check_symbol_table = tc.get_symbol_table()
        except HGPLError as e:
            self._console.insert(END, "ERROR: " + str(e) + "\n\n")
        else:
            self._console.insert(END, "Successfully type checked AST!\nResult: " + tc.get_result().name + "\n\n")
            self._build_symbol_table()
            # self._optimize_button.config(state=NORMAL)
            if tc.get_result() == TypeCheckerResult.PASS or tc.get_result() == TypeCheckerResult.WARN:
                self._interpret_button.config(state=NORMAL)
                self._typecheck_button.config(state=DISABLED)
        finally:
            self._console.see(END)
            self._console.config(state=DISABLED)

    def _command_optimize(self):
        self._interpret_button.config(state=DISABLED)
        self._typecheck_button.config(state=DISABLED)
        self._tokenize_button.config(state=DISABLED)
        self._parse_button.config(state=DISABLED)

    def _command_interpret(self):
        old_ast = deepcopy(self.ast)
        old_table = deepcopy(self.type_check_symbol_table)
        self._result.delete(0, END)

        self._optimize_button.config(state=DISABLED)
        self._typecheck_button.config(state=DISABLED)
        self._tokenize_button.config(state=DISABLED)
        self._parse_button.config(state=DISABLED)

        self._console.config(state=NORMAL)
        self._console.insert(END, "Running interpreter on AST and symbol table...\n")
        try:
            i = Interpreter(self.ast, self._policy_combo.get())
            result = i.evaluate(self.symbol_table, ErrorType.ERROR)
            warns = i.get_warnings()

            if warns:
                self._console.insert(END, "Warnings:\n")
                for w in warns:
                    self._console.insert(END,  "  * " + str(w) + "\n")

            for symbol in self.type_check_symbol_table.symbols():
                if self.symbol_table.exists(symbol):
                    self.type_check_symbol_table.set_value(symbol, self.symbol_table.lookup_value(symbol))
                    self.type_check_symbol_table.switch_type(symbol, self.symbol_table.lookup_type(symbol))
        except HGPLError as e:
            self._console.insert(END, "ERROR: " + str(e) + "\n\n")
        else:
            self._console.insert(END, "Successfully interpreted AST!\nResult: " + result.name + "\n\n")
            self._build_symbol_table()
            self._build_ast()
        finally:
            self._console.see(END)
            self._console.config(state=DISABLED)
            del self.type_check_symbol_table
            del self.ast
            self.type_check_symbol_table = old_table
            self.ast = old_ast

    def _command_reset(self):
        del self.ast
        del self.token_list
        del self.type_check_symbol_table

        self.token_list = None
        self.ast = None
        self.type_check_symbol_table = None
        self._result.delete(0, END)
        self._typecheck.delete(0, END)
        self._build_token_list()
        self._build_ast()
        self._build_symbol_table()

        self._tokenize_button.config(state=NORMAL)
        self._parse_button.config(state=DISABLED)
        self._typecheck_button.config(state=DISABLED)
        self._optimize_button.config(state=DISABLED)
        self._interpret_button.config(state=DISABLED)

        #self._policy_combo.set('')
        self._policy_combo.config(state=NORMAL)

        self._console.config(state=NORMAL)
        self._console.delete('1.0', END)
        self._console.insert(END, "Reset.\n\n")
        self._console.see(END)
        self._console.config(state=DISABLED)


class LexerDemo(object):
    def __init__(self, example_policies=None, example_symbol_table=None):
        self.policies = example_policies
        self.symbol_table = example_symbol_table

        if self.policies is None:
            self.policies = LexerDemo.default_policies()

        if self.symbol_table is None:
            self.symbol_table = LexerDemo.default_symbol_table()

    @staticmethod
    def default_policies():
        return ['user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner',
                'object.required_perms SUBSET user.perms AND user.age >= 18',
                'user.admin OR (user.role = \"doctor\" AND user.id != object.patient)']

    @staticmethod
    def default_symbol_table():
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
                 "user.set": SymbolType.SET,
                 "admin.string": SymbolType.STRING,
                 "admin.int": SymbolType.INT,
                 "admin.float": SymbolType.FLOAT,
                 "admin.set": SymbolType.SET}

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
                "user.set": {1, 2, 3},
                "admin.string": "this is an admin string att",
                "admin.int": -1234,
                "admin.float": -1.1,
                "admin.set": {"this", "is", "a", "set in an admin", "att"}}

        sb.load_mixed_att_val_dict(vals)
        return sb.build()

    def run(self):
        root = Tk()
        root.geometry("986x700+100+100")
        root.title("HGABAC Lexer Demo")
        root.resizable(0,0)
        frame = LexerDemoFrame(root, self.policies, self.symbol_table)
        frame.mainloop()
        #root.destroy()


if __name__ == "__main__":
    demo = LexerDemo()
    demo.run()
