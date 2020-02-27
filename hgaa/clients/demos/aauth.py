from tkinter import *
from tkinter import ttk
from Crypto.PublicKey import RSA
import pprint
import binascii
import textwrap
import time
from datetime import datetime

from hgaa.config import get_conf
from hgaa.attcert import AttributeCertificate, ExportFormat
from hgaa.clients.aauth import AttributeAuthorityClient


class AAuthDemoFrame(Frame):
    ATT_TEST=False
    ATT_TEST_NUM=300

    def __init__(self, parent, aaclient, key, key_size):
        Frame.__init__(self, parent)
        self.parent = parent
        self.key = key
        self.key_size = key_size
        self.default_service_desc = aaclient.service_desc
        self.aaclient = aaclient
        self.pack(fill=BOTH, expand=True)
        self.raw_ac = None
        self.ac = None
        self._build_widgets()

    def _build_widgets(self):
        frame_padx=3
        frame_pady=2
        frame_border=2
        button_width = 20
        button_height = 2

        self._service_frame = LabelFrame(self, relief=RAISED, borderwidth=1, text="Attribute Authority Request")
        self._service_frame.grid(row=0, column=0, sticky=(N,S))

        self._service_desc_frame = LabelFrame(self._service_frame, relief=RAISED, borderwidth=frame_border,
                                              text='Service Location')
        self._service_desc_frame.grid(row=0, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._service_desc_label = Label(self._service_desc_frame, text="Service Description URL: ")
        self._service_desc_label.grid(row=0, column=0)
        self._service_sec_entry = Entry(self._service_desc_frame, width=55)
        self._service_sec_entry.insert(0, self.aaclient.service_desc)
        self._service_sec_entry.grid(row=0, column=1)

        self._service_auth_frame = LabelFrame(self._service_frame, relief=RAISED, borderwidth=frame_border,
                                              text='User Authentication')
        self._service_auth_frame.grid(row=2, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._service_auth_type_label = Label(self._service_auth_frame, text="Auth Type:")
        self._service_auth_type_label.grid(row=1, column=0)
        self._service_auth_type_combo = ttk.Combobox(self._service_auth_frame, width=25, state="readonly")
        self._service_auth_type_combo.grid(row=1, column=1)
        self._service_auth_type_combo['values'] = ['USER PASS']
        self._service_auth_type_combo.current(0)
        self._service_username_label = Label(self._service_auth_frame, text="Username:")
        self._service_username_label.grid(row=2, column=0)
        self._service_user_entry = Entry(self._service_auth_frame, width=25)
        self._service_user_entry.grid(row=2, column=1)
        self._service_pass_label = Label(self._service_auth_frame, text="Password:")
        self._service_pass_label.grid(row=3, column=0)
        self._service_pass_entry = Entry(self._service_auth_frame, width=25, show='*')
        self._service_pass_entry.grid(row=3, column=1)

        self._service_user_entry.insert(0, "dan")
        self._service_pass_entry.insert(0, "admin")

        self._service_key_frame = LabelFrame(self._service_frame, relief=RAISED, borderwidth=frame_border,
                                             text="User Session Key")
        self._service_key_frame.grid(row=3, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._service_key_label = Label(self._service_key_frame, text="Public / Private Key Pair:")
        self._service_key_label.grid(row=0, column=0, columnspan=2)
        self._service_key_text = Text(self._service_key_frame, width=64, height=10)
        if self.key is not None:
            self._service_key_text.insert('1.0', self.key.exportKey().decode('utf-8'))
        self._service_key_text.grid(row=1, column=0, columnspan=2, sticky=(W, E))
        self._service_key_console_scroll = ttk.Scrollbar(self._service_key_frame, orient=VERTICAL,
                                                         command=self._service_key_text.yview)
        self._service_key_text.configure(yscrollcommand=self._service_key_console_scroll)
        self._service_key_console_scroll.grid(row=1, column=2, sticky=(N, S))

        self._service_key_gen_button = Button(self._service_key_frame, text="Generate Key Pair",
                                              command=self._command_generate, width=button_width, height=button_height)
        self._service_key_gen_button.grid(row=2, column=0)
        self._service_key_load = Button(self._service_key_frame, text="Import Key",
                                        command=self._command_load_key, width=button_width, state=DISABLED,
                                        height=button_height)
        self._service_key_load.grid(row=2, column=1)

        self._service_att_frame = LabelFrame(self._service_frame, relief=RAISED, borderwidth=frame_border,
                                             text="Activate Attributes")
        self._service_att_frame.grid(row=4, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._service_att_name_label = Label(self._service_att_frame, text="Attributes by Name:")
        self._service_att_name_label.grid(row=0, column=0)
        self._service_att_id_label = Label(self._service_att_frame, text="Attributes by ID:")
        self._service_att_id_label.grid(row=0, column=4)
        self._service_att_name_list = Listbox(self._service_att_frame, height=10, width=40)
        self._service_att_name_list.grid(row=1, column=0, columnspan=3)
        self._service_att_id_list = Listbox(self._service_att_frame, height=10, width=40)
        self._service_att_id_list.grid(row=1, column=4, columnspan=3)
        self._service_att_name_entry = Entry(self._service_att_frame, width=20)
        self._service_att_name_entry.grid(row=2, column=0)
        self._service_att_id_entry = Entry(self._service_att_frame, width=20)
        self._service_att_id_entry.grid(row=2, column=4)
        self._service_att_name_add = Button(self._service_att_frame, text="Add",
                                              command=self._command_add_name, width=5, height=1)
        self._service_att_name_add.grid(row=2, column=1)
        self._service_att_name_del = Button(self._service_att_frame, text="Delete",
                                            command=self._command_del_name, width=5, height=1)
        self._service_att_name_del.grid(row=2, column=2)
        self._service_att_id_add = Button(self._service_att_frame, text="Add",
                                              command=self._command_add_id, width=5, height=1)
        self._service_att_id_add.grid(row=2, column=5)
        self._service_att_id_del = Button(self._service_att_frame, text="Delete",
                                            command=self._command_del_id, width=5, height=1)
        self._service_att_id_del.grid(row=2, column=6)

        self._service_cmd_frame = LabelFrame(self._service_frame, relief=RAISED, borderwidth=frame_border,
                                             text="Commands")
        self._service_cmd_frame.grid(row=5, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._service_cmd_info_button = Button(self._service_cmd_frame, text="Issue Info Request",
                                              command=self._command_info, width=button_width, height=button_height)
        self._service_cmd_info_button.grid(row=0, column=0)
        self._service_cmd_ac_button = Button(self._service_cmd_frame, text="Issue Attribute Request",
                                              command=self._command_ac, width=button_width, height=button_height)
        self._service_cmd_ac_button.grid(row=0, column=1)
        self._service_cmd_reset_button = Button(self._service_cmd_frame, text="Reset",
                                              command=self._command_reset, width=button_width, height=button_height)
        self._service_cmd_reset_button.grid(row=0, column=2)

        self._result_frame = LabelFrame(self, relief=RAISED, borderwidth=2, text='Request Response')
        self._result_frame.grid(row=1, column=0, sticky=(E,W), columnspan=4)
        self._result_text = Text(self._result_frame, width=232, height=13, state=DISABLED)
        self._result_text.grid(row=1, column=0, columnspan=2, sticky=(W, E))
        self._result_console_scroll = ttk.Scrollbar(self._result_frame, orient=VERTICAL,
                                                         command=self._result_text.yview)
        self._result_text.configure(yscrollcommand=self._result_console_scroll)
        self._result_console_scroll.grid(row=1, column=2, sticky=(N, S))
        self._result_cmd_frame = LabelFrame(self._result_frame, relief=RAISED, borderwidth=frame_border,
                                             text="Commands")
        self._result_cmd_frame.grid(row=5, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._result_cmd_clear_button = Button(self._result_cmd_frame, text="Clear",
                                              command=self._command_clear, width=button_width, height=button_height)
        self._result_cmd_clear_button.grid(row=0, column=2)

        self._ac_frame = LabelFrame(self, relief=RAISED, borderwidth=2, text='Raw Attribute Certificate')
        self._ac_frame.grid(row=0, column=1, sticky=(N,S))
        self._ac_text = Text(self._ac_frame, width=64, height=37, state=DISABLED)
        self._ac_text.grid(row=0, column=0, columnspan=2, sticky=(W, E))
        self._ac_console_scroll = ttk.Scrollbar(self._ac_frame, orient=VERTICAL,
                                                         command=self._ac_text.yview)
        self._ac_text.configure(yscrollcommand=self._ac_console_scroll)
        self._ac_console_scroll.grid(row=0, column=2, sticky=(N, S))
        self._ac_verify_label = Label(self._ac_frame, text="Verified: Not Checked", anchor=W)
        self._ac_verify_label.grid(row=1, column=0, columnspan=2, sticky=(W, E))

        self._ac_cmd_frame = LabelFrame(self._ac_frame, relief=RAISED, borderwidth=frame_border,
                                            text="Commands")
        self._ac_cmd_frame.grid(row=2, column=0, sticky=(E, W), columnspan=2, padx=frame_padx, pady=frame_pady)
        self._ac_cmd_verify_button = Button(self._ac_cmd_frame, text="Verify",
                                           command=self._command_verify, width=button_width-6, height=button_height)
        self._ac_cmd_verify_button.grid(row=0, column=0)
        self._ac_cmd_view_bytes_button = Button(self._ac_cmd_frame, text="View as Bytes",
                                           command=self._command_view_bytes, width=button_width-6, height=button_height)
        self._ac_cmd_view_bytes_button.grid(row=0, column=1)
        self._ac_cmd_view_text_button = Button(self._ac_cmd_frame, text="View as Text",
                                           command=self._command_view_text, width=button_width-6, height=button_height)
        self._ac_cmd_view_text_button.grid(row=0, column=2)
        self._ac_cmd_view_base64_button = Button(self._ac_cmd_frame, text="View as Base64",
                                           command=self._command_view_base64, width=button_width-6, height=button_height)
        self._ac_cmd_view_base64_button.grid(row=0, column=3)
        self._ac_cmd_clear_button = Button(self._ac_cmd_frame, text="Clear",
                                               command=self._command_clear_ac, width=button_width-6, height=button_height)
        self._ac_cmd_clear_button.grid(row=0, column=4)

        self._att_frame = LabelFrame(self, relief=RAISED, borderwidth=2, text='Attribute Certificate Tree Viewer')
        self._att_frame.grid(row=0, column=2, sticky=(N, S))
        self._att_tree = ttk.Treeview(self._att_frame , columns=('value'), height=30)
        self._att_tree.grid(row=0, column=0, sticky=(E, W))
        self._att_tree_scroll = ttk.Scrollbar(self._att_frame, orient=VERTICAL, command= self._att_tree.yview)
        self._att_tree.configure(yscrollcommand=self._att_tree_scroll.set)
        self._att_tree_scroll.grid(row=0, column=1, sticky=(N, S))

        self._att_tree.column('#0', width=250, anchor='center')
        self._att_tree.heading('#0', text='Name')
        self._att_tree.column('value', width=465, anchor='center')
        self._att_tree.heading('value', text='Value')

        if AAuthDemoFrame.ATT_TEST:
            for i in range(0, AAuthDemoFrame.ATT_TEST_NUM):
                self._service_att_name_list.insert(END, 'a%d' % i)

    def _build_ac_tree(self):
        if hasattr(self, '_att_tree') and self._att_tree is not None:
            self._att_tree.pack_forget()
            del self._att_tree

        self._att_tree = ttk.Treeview(self._att_frame , columns=('value'), height=30)
        self._att_tree.grid(row=0, column=0, sticky=(E, W))
        self._att_tree_scroll = ttk.Scrollbar(self._att_frame, orient=VERTICAL, command= self._att_tree.yview)
        self._att_tree.configure(yscrollcommand=self._att_tree_scroll.set)
        self._att_tree_scroll.grid(row=0, column=1, sticky=(N, S))

        self._att_tree.column('#0', width=250, anchor='center')
        self._att_tree.heading('#0', text='Name')
        self._att_tree.column('value', width=465, anchor='center')
        self._att_tree.heading('value', text='Value')

        self._att_tree_info = self._att_tree.insert('', 'end', text='Information')
        self._att_tree_info_version = self._att_tree.insert(self._att_tree_info, 'end', text='version',
                                                            values=[self.ac.info.version])
        serial_hex = ('0x%0.2X' % self.ac.info.serial)[2:]
        self._att_tree_info_serial = self._att_tree.insert(self._att_tree_info, 'end', text='serial',
                                                           values=[serial_hex])
        issued_date = datetime.fromtimestamp(self.ac.info.issued).strftime('%Y-%m-%d %I:%M:%S%p %Z')
        self._att_tree_info_issued = self._att_tree.insert(self._att_tree_info, 'end', text='issued',
                                                           values=[issued_date])

        self._att_tree_issuer = self._att_tree.insert('', 'end', text='Issuer')
        self._att_tree_issuer_pub_key = self._att_tree.insert(self._att_tree_issuer, 'end', text='pub_key',
                                                              values=[self.ac.issuer.pub_key])
        self._att_tree_issuer_key_algo = self._att_tree.insert(self._att_tree_issuer, 'end', text='key_algo',
                                                               values=[self.ac.issuer.key_algo])
        self._att_tree_issuer_uid = self._att_tree.insert(self._att_tree_issuer, 'end', text='uid',
                                                          values=[self.ac.issuer.uid])
        if self.ac.issuer.name is not None:
            self._att_tree_issuer_name = self._att_tree.insert(self._att_tree_issuer, 'end', text='name',
                                                               values=[self.ac.issuer.name])
        if self.ac.issuer.url is not None:
            self._att_tree_issuer_url = self._att_tree.insert(self._att_tree_issuer, 'end', text='url',
                                                              values=[self.ac.issuer.url])

        self._att_tree_holder = self._att_tree.insert('', 'end', text='Holder')
        self._att_tree_holder_pub_key = self._att_tree.insert(self._att_tree_holder, 'end', text='pub_key',
                                                              values=[self.ac.holder.pub_key])
        self._att_tree_holder_key_algo = self._att_tree.insert(self._att_tree_holder, 'end', text='key_algo',
                                                               values=[self.ac.holder.key_algo])
        self._att_tree_holder_uid = self._att_tree.insert(self._att_tree_holder, 'end', text='uid',
                                                          values=[self.ac.holder.uid])
        if self.ac.holder.name is not None:
            self._att_tree_holder_name = self._att_tree.insert(self._att_tree_holder, 'end', text='name',
                                                               values=[self.ac.holder.name])

        self._att_tree_att_set = self._att_tree.insert('', 'end', text='Attribute Set')
        for att in self.ac.att_set:
            att_widget = self._att_tree.insert(self._att_tree_att_set, 'end', text=att.att_id)
            att_widget_id = self._att_tree.insert(att_widget, 'end', text='id', values=[att.att_id])
            if att.att_name is not None:
                att_widget_name = self._att_tree.insert(att_widget, 'end', text='name', values=[att.att_name])
            att_widget_type = self._att_tree.insert(att_widget, 'end', text='type', values=[att.att_type.name])
            if att.att_value is not None and att.att_value.lower() != 'none':
                att_widget_val = self._att_tree.insert(att_widget, 'end', text='value', values=[att.att_value])

        self._att_tree_rev_rules = self._att_tree.insert('', 'end', text='Revocation Rules')
        after_date = datetime.fromtimestamp(self.ac.rev_rules.valid_after).strftime('%Y-%m-%d %I:%M:%S%p %Z')
        self._att_tree_rev_rules_valid_after = self._att_tree.insert(self._att_tree_rev_rules, 'end',
                                                                     text='valid_after',
                                                                     values=[after_date])
        before_date = datetime.fromtimestamp(self.ac.rev_rules.valid_before).strftime('%Y-%m-%d %I:%M:%S%p %Z')
        self._att_tree_rev_rules_valid_before = self._att_tree.insert(self._att_tree_rev_rules, 'end',
                                                                      text='valid_before',
                                                                      values=[before_date])
        if self.ac.rev_rules.url is not None:
            self._att_tree_rev_rules_url = self._att_tree.insert(self._att_tree_rev_rules, 'end',
                                                                 text='url', values=[self.ac.rev_rules.url])
        if self.ac.rev_rules.extra_bytes is not None:
            self._att_tree_rev_rules_extra_bytes = self._att_tree.insert(self._att_tree_rev_rules, 'end',
                                                                         text='extra_bytes',
                                                                         values=[self.ac.rev_rules.extra_bytes])

        self._att_tree_del_rules = self._att_tree.insert('', 'end', text='Delegation Rules')
        if self.ac.del_rules is not None and self.ac.del_rules.extra_bytes is not None:
            self._att_tree_del_rules_extra_bytes = self._att_tree.insert(self._att_tree_del_rules, 'end',
                                                                         text='extra_bytes',
                                                                         values=[self.ac.del_rules.extra_bytes])

        self._att_tree_ext = self._att_tree.insert('', 'end', text='Extensions')
        if self.ac.extensions is not None:
            for ext in self.ac.extensions:
                ext_widget = self._att_tree.insert(self._att_tree_ext, 'end', text=ext.eid)
                ext_widget_eid = self._att_tree.insert(ext_widget, 'end', text='eid', values=[ext.eid])
                ext_widget_extra_bytes = self._att_tree.insert(ext_widget, 'end', text='extra_bytes',
                                                               values=[ext.extra_bytes])

        self._att_tree_sig = self._att_tree.insert('', 'end', text='Signature')
        if self.ac.signature is not None:
            self._att_tree_sig_sig_algo = self._att_tree.insert(self._att_tree_sig, 'end', text='sig_algo',
                                                                values=[self.ac.signature.sig_algo])
            sig_val_hex = binascii.hexlify(self.ac.signature.sig_value)
            self._att_tree_sig_sig_value = self._att_tree.insert(self._att_tree_sig, 'end', text='sig_value',
                                                                 values=[sig_val_hex])

    def _command_generate(self):
        self.key = RSA.generate(self.key_size)
        self._service_key_text.delete('1.0', END)
        self._service_key_text.insert('1.0', self.key.exportKey().decode('utf-8'))

    def _command_load_key(self):
        pass

    def _command_add_name(self):
        name = self._service_att_name_entry.get()
        if name is not None and name.strip() != '' and name not in self._service_att_name_list.get(0, END):
            self._service_att_name_list.insert(END, name)
        self._service_att_name_entry.delete(0, END)

    def _command_del_name(self):
        sel = self._service_att_name_list.curselection()
        self._service_att_name_list.delete(sel)

    def _command_add_id(self):
        id = self._service_att_id_entry.get()
        if id is not None and id.strip() != '' and id not in self._service_att_id_list.get(0, END):
            self._service_att_id_list.insert(END, id)
        self._service_att_id_entry.delete(0, END)

    def _command_del_id(self):
        sel = self._service_att_id_list.curselection()
        self._service_att_id_list.delete(sel)

    def _command_info(self):
        if self.aaclient.service_desc != self._service_sec_entry.get():
            self.aaclient.update_service(url=self._service_sec_entry.get())
        try:
            result = pprint.pformat(self.aaclient.info())
        except Exception as e:
            result = e

        self._result_text.config(state=NORMAL)
        self._result_text.delete('1.0', END)
        self._result_text.insert('1.0', result)
        self._result_text.config(state=DISABLED)

    def _command_ac(self):
        if self.aaclient.service_desc != self._service_sec_entry.get():
            self.aaclient.update_service(url=self._service_sec_entry.get())
        attribute_names = self._service_att_name_list.get(0, END)
        attribute_ids = self._service_att_id_list.get(0, END)
        self.aaclient.credentials = {'type': self._service_auth_type_combo.current(),
                                     'username': self._service_user_entry.get(),
                                     'password': self._service_pass_entry.get()}

        try:
            t0 = time.time()
            result = self.aaclient.attribute_request(attribute_names=attribute_names, attribute_ids=attribute_ids,
                                                     key=self.key)
            t1 = time.time()
        except Exception as e:
            self._result_text.config(state=NORMAL)
            self._result_text.delete('1.0', END)
            self._result_text.insert('1.0', e)
            self._result_text.config(state=DISABLED)
            return

        attachment = None

        while True:
            try:
                attachment = result['data'].read()
                AttributeAuthorityClient.LOG.info('Attachment read successfully!')
                break
            except ValueError:
                AttributeAuthorityClient.LOG.error('Attachment could not be read. Trying request again...')
                result = self.aaclient.attribute_request(attribute_names=attribute_names, attribute_ids=attribute_ids,
                                                         key=self.key)
        result['data'].close()

        self.key = self.aaclient.last_key
        self._service_key_text.delete('1.0', END)
        self._service_key_text.insert('1.0', self.key.exportKey().decode('utf-8'))

        att_hex = binascii.hexlify(attachment).decode('utf-8').upper()
        att_hex = " ".join(att_hex[i:i + 2] for i in range(0, len(att_hex), 2))

        self.raw_ac = attachment
        self.ac = AttributeCertificate.decode(bytearray(self.raw_ac))

        self._result_text.config(state=NORMAL)
        self._result_text.delete('1.0', END)
        self._result_text.insert('1.0', '\n\n' + 'Request took %s seconds.\n\n' % str(t1 - t0))
        self._result_text.insert(END, pprint.pformat(result))
        self._result_text.insert(END, '\n\n' + 'Attachment:\n' + textwrap.fill(att_hex, 150))
        self._result_text.config(state=DISABLED)

        self._ac_text.config(state=NORMAL)
        self._ac_text.delete('1.0', END)
        self._ac_text.insert('1.0', textwrap.fill(att_hex, 70))
        self._ac_text.config(state=DISABLED)

        self._build_ac_tree()

    def _command_clear(self):
        self._result_text.config(state=NORMAL)
        self._result_text.delete('1.0', END)
        self._result_text.config(state=DISABLED)

    def _command_reset(self):
        self._service_att_id_entry.delete(0, END)
        self._service_att_name_entry.delete(0, END)
        self._service_att_id_list.delete(0, END)
        self._service_att_name_list.delete(0, END)
        self._service_key_text.delete('1.0', END)
        self.key = None
        self._service_user_entry.delete(0, END)
        self._service_pass_entry.delete(0, END)
        self._service_sec_entry.delete(0, END)
        self._service_sec_entry.insert(0, self.default_service_desc)
        self._service_auth_type_combo.current(0)

    def _command_clear_ac(self):
        self._ac_verify_label['text'] = 'Verified: Not Checked'
        self._ac_text.config(state=NORMAL)
        self._ac_text.delete('1.0', END)
        self._ac_text.config(state=DISABLED)

    def _command_view_bytes(self):
        if self.raw_ac is not None:
            att_hex = binascii.hexlify(self.raw_ac).decode('utf-8').upper()
            att_hex = " ".join(att_hex[i:i + 2] for i in range(0, len(att_hex), 2))
            self._ac_text.config(state=NORMAL)
            self._ac_text.delete('1.0', END)
            self._ac_text.insert('1.0', textwrap.fill(att_hex, 70))
            self._ac_text.config(state=DISABLED)

    def _command_view_text(self):
        text = self.ac.export_ac(format=ExportFormat.TEXT)
        self._ac_text.config(state=NORMAL)
        self._ac_text.delete('1.0', END)
        self._ac_text.insert('1.0', 'Text size: %d bytes.\n\n' % len(text))
        self._ac_text.insert(END, text)
        self._ac_text.config(state=DISABLED)

    def _command_view_base64(self):
        b64 = self.ac.export_ac(format=ExportFormat.BASE64FULL)
        self._ac_text.config(state=NORMAL)
        self._ac_text.delete('1.0', END)
        self._ac_text.insert('1.0', b64)
        self._ac_text.config(state=DISABLED)

    def _command_verify(self):
        if self.ac.verify_signature():
            self._ac_verify_label['text'] = 'Verified: TRUE'
        else:
            self._ac_verify_label['text'] = 'Verified: FALSE'


class AAuthDemo(object):
    def __init__(self):
        self.aaclient = AttributeAuthorityClient()
        self.key = None
        self.key_size = int(get_conf('KEY_SIZE', False, 'AAUTH'))

    def run(self):
        root = Tk()
        root.geometry("1880x1000+10+10")
        root.title("HGABAC AAuth Client Demo")
        root.resizable(0,0)
        frame = AAuthDemoFrame(root, self.aaclient, self.key, self.key_size)
        frame.mainloop()



if __name__ == "__main__":
    demo = AAuthDemo()
    demo.run()