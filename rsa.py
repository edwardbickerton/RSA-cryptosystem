#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""@author: satsuma.blog ."""
##############
# To Do List #
##############
# re write all the popups, hide and show them rather than destroy and create.
# reduce duplicate code with more object oriented style
# clean up code

from random import SystemRandom, randint
from hashlib import sha256, sha512
import tkinter as tk
from tkinter import ttk, messagebox
import os.path
from os import remove

####################
# Global Variables #
####################

default_bit_length = 512
default_exponent = 65537
launch_gui = True

###########################
# Number Theory Functions #
###########################


def gcd_ext(a: int, b: int) -> tuple:
    """
    Output (gcd,x,y) such that gcd=ax+by.

    Parameters
    ----------
    a : int
        DESCRIPTION.
    b : int
        DESCRIPTION.

    Returns
    -------
    tuple
        DESCRIPTION.

    """
    if not(a % 1 == 0 and b % 1 == 0):
        print("Need to use integers for gcd.")
        return None
    if a == 0:
        return (abs(b), 0, abs(b)//b)
    else:
        quot = b//a

        g, x, y = gcd_ext(b % a, a)
        return (g, y - quot * x, x)


def modular_inverse(a: int, b: int) -> int:
    """
    Return the multiplicative inverse of a modulo b.

    Returns none if gcd(a,b) != 1

    Parameters
    ----------
    a : int
        DESCRIPTION.
    b : int
        DESCRIPTION.

    Returns
    -------
    int
        DESCRIPTION.

    """
    (g, x, y) = gcd_ext(a, b)
    if not g == 1:
        print('The numbers are not comprime')
        return None
    x = x % b
    return x


def miller_rabin(p: int, a: int) -> bool:
    """
    Required for function is_prime.

    Parameters
    ----------
    p : prime being tested
    a : witness

    Returns
    -------
    True if prime, else False.
    """
    e = p-1
    bin_string = bin(e)[2:]
    n = 1

    for i in range(len(bin_string)):

        # Applying the ROO test.
        n_squared = pow(n, 2, p)
        if n_squared == 1:
            if (n != 1) and (n != p-1):
                return False

        if bin_string[i] == '1':
            n = (n_squared*a) % p
        else:
            n = n_squared

    # Applying the FLT test.
    if n != 1:
        return False

    return True


def is_prime(p: int, num_wit: int = 50) -> bool:
    """
    Test if an integer is prime.

    Parameters
    ----------
    p : int
        DESCRIPTION.
    num_wit : int, optional
        DESCRIPTION. The default is 50.

    Returns
    -------
    bool
        DESCRIPTION.

    """
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    if p <= 37:
        return p in small_primes

    if p % 2 == 0:
        return False

    if p <= pow(2, 64):
        for witness in small_primes:
            if not miller_rabin(p, witness):
                return False
        return True

    else:
        for i in range(num_wit):
            if not miller_rabin(p, randint(2, p-2)):
                return False
        return True


def random_prime(Bit_Length: int = default_bit_length) -> int:
    """
    Generate a random prime.

    Parameters
    ----------
    Bit_Length : int, optional
        The number of digits in the binary representation of the prime.
        e.g. a 512 bit prime is between 2**511 and 2**512

    Returns
    -------
    int
        A random prime.
    """
    while True:
        p = SystemRandom().getrandbits(Bit_Length)
        if p >= pow(2, Bit_Length-1):
            if is_prime(p):
                return p


def decimal_to_base(number: int, alphabet: list = [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)]) -> str:
    """


    Parameters
    ----------
    number : int
        DESCRIPTION.
    alphabet : list, optional
        DESCRIPTION. The default is [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)].

    Returns
    -------
    str
        DESCRIPTION.

    """
    base = len(alphabet)
    i = 1
    while True:
        if number//pow(base, i) == 0:
            i -= 1
            break
        i += 1
    base_list = []
    for j in range(i+1):
        base_list.append(alphabet[0])
    l = len(base_list)
    for j in range(l):
        x = pow(base, l-j-1)
        base_list[j] = alphabet[number//x]
        number -= alphabet.index(base_list[j])*x
    base_string = ''.join(base_list)
    return base_string


def base_to_decimal(base_string: str, alphabet: list = [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)]) -> int:
    decimal = 0
    base = len(alphabet)
    for i in range(1, len(base_string)+1):
        decimal += alphabet.index(base_string[-i])*pow(base, i-1)
    return decimal

################
# RSA Back End #
################


class Message(object):
    """Represents a message to be signed, encrypted and sent."""
    start_of_signatures_message = '\n\n----------------------SIGNATURES----------------------\n'
    separator = '_'
    allowed_characters = [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)] + [' ', '.', chr(10), ',', "'", '"',
                                                                                                                             '`', '!', '?', ':', ';', '(', ')', '[', ']', '{', '}', '/', '|', '\\', '-', '_', '@', '%', '&', '#', '~', '=', '+', '*', '<', '>', '^', '$','€','£']

    def __init__(self, string: str):
        unsupported_chars = ''.join(list(dict.fromkeys(
            [char for char in string if char not in Message.allowed_characters])))
        if unsupported_chars != '':
            print(
                '\nWARNING: message contains unsupported character(s): ' + unsupported_chars)
        self.string = string
        self.signatures = {}
        if Message.start_of_signatures_message in string:
            self.string = string[:string.index(
                Message.start_of_signatures_message)]
            signatures_string = string[string.index(
                Message.start_of_signatures_message) + len(Message.start_of_signatures_message):]
            labels_list = [i for i in range(
                len(signatures_string)) if signatures_string[i] == ':']
            other_list = [signatures_string[labels_list[j]+2:labels_list[j+1]]
                          for j in range(len(labels_list)-1)] + [signatures_string[labels_list[-1]+2:]]
            for i in range(len(other_list)//2):
                self.signatures[str(import_key(other_list[i*2]))] = base_to_decimal(
                    other_list[i*2+1][:other_list[i*2+1].index("\n")])
        self.h = int(sha256(self.string.encode()).hexdigest(), 16)

        self.verify()

    def __str__(self):
        text_string = self.string
        if self.signatures != {}:
            text_string += Message.start_of_signatures_message
            for pub_key in self.signatures:
                text_string += '\nPUBLIC KEY:\n' + pub_key + '\nSIGNATURE:\n' + \
                    decimal_to_base(self.signatures[pub_key]) + '\n'
        return text_string

    def verify(self):
        reverse_dict = {}
        for key in Key_Store.public_keys:
            reverse_dict[str(Key_Store.public_keys[key])] = key
        txt = ''
        if self.signatures == {}:
            txt = 'Message has not been signed.'
        else:
            valid_sigs = []
            invalid_sigs = []
            for pub_key in self.signatures:
                if self.h == pow(self.signatures[pub_key], import_key(pub_key).e, import_key(pub_key).N):
                    if str(pub_key) in reverse_dict:
                        valid_sigs.append(reverse_dict[pub_key])
                    else:
                        valid_sigs.append(str(pub_key))
                else:
                    if str(pub_key) in reverse_dict:
                        invalid_sigs.append(reverse_dict[pub_key])
                    else:
                        invalid_sigs.append(str(pub_key))
            if invalid_sigs != []:
                if txt != '':
                    txt += '\n'
                txt += 'WARNING! \nInvalid signature(s) from:\n' + '\n'.join(invalid_sigs)
            if valid_sigs != []:
                if txt != '':
                    txt += '\n'
                txt += 'Valid signature(s) from:\n' + '\n'.join(valid_sigs)
        return txt


def de_format(any_string: str) -> list:
    separators = [i for i in range(
        len(any_string)) if any_string[i] == Message.separator]
    de_formatted = [base_to_decimal(
        any_string[separators[i]+1:separators[i+1]]) for i in range(len(separators)-1)]
    return de_formatted


class Key(object):
    """Represents a generic key."""
    prefix = None
    def __str__(self):
        string = self.prefix + Message.separator
        for i in range(2):
            string += decimal_to_base(list(self.__dict__.values())
                                      [i]) + Message.separator
        return string


class Private_Key(Key):
    """Represents a private key."""

    def __init__(self, p: int = 'new', q: int = 'new', Bit_Length: int = default_bit_length, label: str = ''):
        self.p = p
        self.q = q
        if p == 'new' or q == 'new':
            print('\nGenerating two random ' + str(Bit_Length) +
                  ' bit primes to form a new private key...')
            self.p = random_prime(Bit_Length)
            self.q = random_prime(Bit_Length)
        self.pub_key = Public_Key(self.p*self.q, label=label)
        self.d = modular_inverse(
            self.pub_key.e, (self.pub_key.N - self.p - self.q + 1))
        if label == '':
            self.label = str(Bit_Length)+'_Bit_Private_Key'
        self.label = label

    prefix = 'privkey'

    def decrypt(self, ciphertext: str) -> Message:
        cipher_list = de_format(ciphertext)
        sub_message_decimal_list = [str(pow(c, self.d, self.pub_key.N))[
            1:] for c in cipher_list]
        sub_message_list = [[Message.allowed_characters[int(
            decimal[2*i:2*i+2])] for i in range(len(decimal)//2)] for decimal in sub_message_decimal_list]
        return Message(''.join([''.join(sub_message) for sub_message in sub_message_list]))

    def sign(self, message: Message) -> dict:
        message.signatures[str(self.pub_key)] = pow(
            message.h, self.d, self.pub_key.N)
        return message.signatures


class Public_Key(Key):
    """Represents a public key."""

    def __init__(self, N: int, e: int = default_exponent, label: str = ''):
        self.N = N
        self.e = e
        if label == '':
            self.label = str(len(bin(N)[2:]))+'_Bit_Public_Key'
        self.label = label

    prefix = 'pubkey'

    def encrypt(self, message: Message) -> str:
        sub_message_chr_length = int((len(bin(self.N)[2:])/2)*0.3)
        text_string = str(message)
        number_of_sub_messages = len(text_string)//sub_message_chr_length
        sub_message_list = [text_string[i*sub_message_chr_length:(i+1)*sub_message_chr_length] for i in range(
            number_of_sub_messages)] + [text_string[number_of_sub_messages*sub_message_chr_length:]]
        decimal_list = [['%.2d' % Message.allowed_characters.index(
            char) for char in sub_message] for sub_message in sub_message_list]
        encrypted_list = [pow(int('1' + ''.join(i)), self.e, self.N)
                          for i in decimal_list]
        return 'ciphertext' + Message.separator + Message.separator.join([decimal_to_base(i) for i in encrypted_list]) + Message.separator


def import_key(string: str):
    if string[:len(Private_Key.prefix)] == Private_Key.prefix:
        p, q = de_format(string)
        return Private_Key(p, q)

    if string[:len(Public_Key.prefix)] == Public_Key.prefix:
        N, e = de_format(string)
        return Public_Key(N, e)

    print("ERROR: No valid key!")
    return

def password_priv_key(password:str, pub_key: Public_Key = None)-> Private_Key:
    password_hash = int(sha512(password.encode()).hexdigest(), 16)
    p = password_hash
    while True:
        if is_prime(p):
            break
        else:
            p+=1
    if pub_key == None:
        q = random_prime(512)
        priv_key = Private_Key(p,q)
    else:
        q = pub_key.N//p
        priv_key = Private_Key(p,q)
    return priv_key

def test():
    """
    Test if everything is working.

    Returns
    -------
    None.

    """
    print('TESTING...')
    Alice_Key = Private_Key()
    print("Alice's Key Pair:\n\n" + str(Alice_Key) +
          '\n\n' + str(Alice_Key.pub_key))
    Bob_Key = Private_Key()
    print("Bob's Key Pair:\n\n" + str(Bob_Key) + '\n\n' + str(Bob_Key.pub_key))
    assert Bob_Key.p != Alice_Key.p
    assert Bob_Key.p != Alice_Key.q
    assert Bob_Key.q != Alice_Key.p
    assert Bob_Key.q != Alice_Key.q
    assert Bob_Key.p != Bob_Key.q
    assert Alice_Key.p != Alice_Key.q
    string = """In common parlance, randomness is the apparent or actual lack
of pattern or predictability in events.[1][2] A random sequence of events,
symbols or steps often has no order and does not follow an intelligible pattern
or combination. Individual random events are, by definition, unpredictable, but
if the probability distribution is known, the frequency of different outcomes
over repeated events (or "trials") is predictable.[3][note 1] For example, when
throwing two dice, the outcome of any particular roll is unpredictable, but a
sum of 7 will tend to occur twice as often as 4. In this view, randomness is
not haphazardness; it is a measure of uncertainty of an outcome. Randomness
applies to concepts of chance, probability, and information entropy."""
    print("\nAlice wants to send Bob the message:\n\n" + string)
    Alice_message = Message(string)
    print("\nShe signs it then encrypts it with Bob's public key.\n")
    Alice_Key.sign(Alice_message)
    print(Alice_message)
    print(Alice_message.verify())
    ciphertext = import_key(str(Bob_Key.pub_key)).encrypt(Alice_message)
    print(ciphertext)
    print('\nBob decrypts this using his private key.\n')
    decrypted_message = Bob_Key.decrypt(ciphertext)
    assert decrypted_message.string == string
    print(decrypted_message)
    print("""Bob decides to edit the message and then sign the message as well
          as then sending it back to Alice.\n""")
    new_message = Message('Bob is awesome! ' + str(decrypted_message))
    Bob_Key.sign(new_message)
    print(new_message)
    ciphertext2 = import_key(str(Alice_Key.pub_key)).encrypt(new_message)
    print(ciphertext2)
    print("""\nAlice decrypts the message, noticing that her signature is no
longer valid as Bob edited the message.\n""")
    decrypted_message2 = Alice_Key.decrypt(ciphertext2)
    print(decrypted_message2)
    print(decrypted_message2.verify())
    return


#############
# Key Store #
#############

class Key_Store(object):
    private_keys = {}
    public_keys = {}
    password = None
    password_pub_key = None
    key_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'keys.txt')

    def read_keys(event = None):
        with open(Key_Store.key_file, 'r') as f:
            raw_list = f.readlines()
            f.close()
            pass
        Key_Store.password_pub_key = import_key(raw_list[0])
        keys_ciphertext = raw_list[1]
        keys_message = password_priv_key(Key_Store.password, Key_Store.password_pub_key).decrypt(keys_ciphertext)
        if 'Valid signature(s) from:\n'+str(Key_Store.password_pub_key) in keys_message.verify():
            print('\nkeys.txt has not been tampered with')
            decrypted_list = str(keys_message).split()
            decrypted_keys_list = decrypted_list[:decrypted_list.index(Message.start_of_signatures_message.strip())]
            for i in range(len(decrypted_keys_list)//2):
                label = decrypted_keys_list[2*i]
                try:
                    key = import_key(decrypted_keys_list[2*i+1])
                except:
                    key = None
                if type(key) == Private_Key:
                    key.label = label
                    Key_Store.private_keys[key.label] = key
                elif type(key) == Public_Key:
                    key.label = label
                    Key_Store.public_keys[key.label] = key
                else:
                    pass

        else:
            print('\nWARNING: keys.txt has been tampered with')

        for key_label in Key_Store.private_keys:
            Key_Store.public_keys[key_label] = Key_Store.private_keys[key_label].pub_key


    def write_keys(event=None):
        if Key_Store.password_pub_key == None:
            print('\nERROR! Failed to write. No Key_Store.password_pub_key')
            return
        text = ''
        remove(Key_Store.key_file)
        for key_label in Key_Store.public_keys:
            if key_label not in Key_Store.private_keys:
                text+= str(key_label)+'\n'+str(Key_Store.public_keys[key_label])+'\n'

        for key_label in Key_Store.private_keys:
            text+= str(key_label)+'\n'+str(Key_Store.private_keys[key_label])+'\n'
        keys_message = Message(text)
        password_priv_key(Key_Store.password, Key_Store.password_pub_key).sign(keys_message)
        keys_ciphertext = Key_Store.password_pub_key.encrypt(keys_message)
        with open(Key_Store.key_file, 'w') as f:
            f.write(str(Key_Store.password_pub_key)+'\n'+keys_ciphertext)
            f.close()
            pass



#######
# GUI #
#######

class Main_Window(object):
    def __init__(self):
        self.root= tk.Tk()
        self.root.title('RSA cryptosystem')

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        self.style = ttk.Style()
        self.theme_var = tk.StringVar()

        root_width=800
        root_height=600

        positionRight = int(self.root.winfo_screenwidth()/2 - root_width/2 )
        positionDown = int(self.root.winfo_screenheight()/2 - root_height/2 ) - 50

        self.root.geometry("{}x{}+{}+{}".format(root_width, root_height, positionRight, positionDown))

main_window = Main_Window()
main_window.root.withdraw()

#################
# Key selection #
#################

key_selection_frame = ttk.Frame(main_window.root)
key_selection_frame.columnconfigure(1, weight=1)
key_selection_frame.grid(row=0, column=0, sticky=tk.N +
                         tk.E+tk.S+tk.W, padx=10, pady=4)


class Key_selection(object):
    def __init__(self, label: str, row: int,):
        ttk.Label(key_selection_frame, text=label).grid(
            row=row, column=0, sticky=tk.W)
        self.key_var = tk.StringVar()
        self.options = ttk.OptionMenu(
            key_selection_frame, self.key_var, "No Keys (click 'Import')")
        self.options.grid(row=row, column=1, sticky=tk.W+tk.E, padx=25)


private_key_selection = Key_selection("Private Key:", 0)
public_key_selection = Key_selection("Public Key:", 1)


class import_export_btns(object):
    def __init__(self, label, row):
        self.btn = tk.Button(key_selection_frame, text=label, padx=2)
        self.btn.grid(row=row, column=2)


import_btn = import_export_btns('Import', 0)
export_btn = import_export_btns('Export', 1)

########################################
##### Message and Ciphertext boxes #####
########################################

message_frame = ttk.Frame(main_window.root)
message_frame.grid(row=1, sticky=tk.N+tk.E+tk.S+tk.W, ipadx=2, ipady=2)
for i in range(2):
    message_frame.columnconfigure(i, weight=1)
message_frame.rowconfigure(0, weight=1)


class Message_box(object):
    def __init__(self, label, column):
        self.frame = ttk.LabelFrame(message_frame, text=label)
        for i in range(2):
            self.frame.columnconfigure(i, weight=1)
        self.frame.rowconfigure(0, weight=1)
        self.frame.grid(row=0, column=column,
                        sticky=tk.N+tk.E+tk.S+tk.W, padx=2, pady=4)
        self.text = tk.Text(self.frame)
        self.text.grid(row=0, column=0, sticky=tk.N +
                       tk.E+tk.S+tk.W, columnspan=2)


message_input = Message_box("Message:", 0)
ciphertext_input = Message_box("Ciphertext:", 1)

###########
# Buttons #
###########


class Lower_btn(object):
    """Represents the lower buttons."""

    def __init__(self, label: str, frame, column: int):
        self.btn = ttk.Button(frame, text=label)
        self.btn.grid(row=1, column=column, sticky=tk.E+tk.W, padx=2, ipady=2)


sign_btn = Lower_btn('Sign', message_input.frame, 0)
encrypt_btn = Lower_btn('Encrypt', message_input.frame, 1)
decrypt_btn = Lower_btn('Decrypt', ciphertext_input.frame, 0)
verify_btn = Lower_btn('Verify', ciphertext_input.frame, 1)

###################################
# Callback Functions and Bindings #
###################################

def Sign():
    if private_key_selection.key_var.get() not in Key_Store.private_keys:
        messagebox.showwarning(title="No Private Key", message="Select a private key")
        return
    priv_key = Key_Store.private_keys[private_key_selection.key_var.get()]
    message = Message(message_input.text.get('1.0', tk.END))
    priv_key.sign(message)
    message_input.text.delete('1.0', tk.END)
    message_input.text.insert('1.0', str(message))


sign_btn.btn.configure(command=Sign)


def Encrypt():
    if public_key_selection.key_var.get() not in Key_Store.public_keys:
        messagebox.showwarning(title="No Public Key", message="Select a public key")
        return
    pub_key = Key_Store.public_keys[public_key_selection.key_var.get()]
    message = Message(message_input.text.get('1.0', tk.END))
    unsupported_chars = [i for i in message.string if i not in Message.allowed_characters]
    unsupported_chars = list(dict.fromkeys(unsupported_chars))
    if unsupported_chars != []:
        messagebox.showwarning(title="Unsupported Character", message="ERROR!\nMessage contains unsupported character(s):\n"+', '.join(unsupported_chars))
        return
    ciphertext = pub_key.encrypt(message)
    message_input.text.delete('1.0', tk.END)
    message_input.text.insert('1.0', ciphertext)


encrypt_btn.btn.configure(command=Encrypt)


def Decrypt():
    if private_key_selection.key_var.get() not in Key_Store.private_keys:
        messagebox.showwarning(title="No Private Key", message="Select a private key")
        return
    priv_key = Key_Store.private_keys[private_key_selection.key_var.get()]
    ciphertext = ciphertext_input.text.get('1.0', tk.END)
    try:
        message = priv_key.decrypt(ciphertext)
    except:
        messagebox.showwarning(title="Wrong private key", message="Wrong private key")
        return
    message = priv_key.decrypt(ciphertext)
    ciphertext_input.text.delete('1.0', tk.END)
    ciphertext_input.text.insert('1.0', str(message))

decrypt_btn.btn.configure(command=Decrypt)


def Verify():
    message = Message(ciphertext_input.text.get('1.0', tk.END))
    verify_txt = message.verify()

    messagebox.showinfo("Signature verification", verify_txt)


verify_btn.btn.configure(command=Verify)


def update_key_OptionMenu():
    if list(Key_Store.private_keys) != []:
        private_key_selection.key_var.set(list(Key_Store.private_keys)[0])
        private_key_selection.options["menu"].delete(0, tk.END)
        for key in list(Key_Store.private_keys):
            private_key_selection.options["menu"].add_command(
                label=key, command=tk._setit(private_key_selection.key_var, key))
    else:
        private_key_selection.key_var.set("No Keys (click 'Import')")
        private_key_selection.options["menu"].delete(0, tk.END)
    if list(Key_Store.public_keys) != []:
        public_key_selection.key_var.set(list(Key_Store.public_keys)[0])
        public_key_selection.options["menu"].delete(0, tk.END)
        for key in list(Key_Store.public_keys):
            public_key_selection.options["menu"].add_command(
                label=key, command=tk._setit(public_key_selection.key_var, key))
    else:
        public_key_selection.key_var.set("No Keys (click 'Import')")
        public_key_selection.options["menu"].delete(0, tk.END)


def Import(event=None):
    new_key = False
    if event:
        new_key = True
    popup = tk.Toplevel(main_window.root)
    popup.title('Import Key')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)

    popup_width=450
    popup_height=165
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)

    label_frame = ttk.LabelFrame(popup, text='Label')
    label_frame.pack(fill=tk.BOTH, padx=4)
    label_var = tk.StringVar()
    label_entry = tk.Entry(label_frame, textvariable=label_var)
    label_entry.pack(fill=tk.BOTH)
    label_entry.focus_set()

    key_frame = ttk.LabelFrame(popup, text='Key')
    key_frame.pack(fill=tk.BOTH, padx=4)
    key_txt = tk.Text(key_frame, height=3)
    key_txt.pack(fill=tk.BOTH)

    option_frame = ttk.Frame(popup)
    option_frame.pack()

    ttk.Label(option_frame, text="Bit length:").grid(column=0, row=0)

    bit_length_choice = tk.IntVar()
    ttk.OptionMenu(option_frame, bit_length_choice, 2**9, 2**8, 2 **
                   9, 2**10, 2**11, 2**12).grid(column=1, row=0, padx=2, pady=6)

    # New Key button
    def new():
        key_txt.delete('1.0', tk.END)
        key_txt.insert('1.0', str(Private_Key(
            Bit_Length=bit_length_choice.get())))

    if new_key == True:
        new()
    else:
        key_txt.delete('1.0',tk.END)

    ttk.Button(option_frame, text="New Private Key",
               command=new).grid(column=2, row=0, padx=4)

    # Save button
    def save(event=None):
        key = import_key(key_txt.get('1.0', tk.END))
        label = label_var.get()
        label = ''.join([label[i] for i in range(len(label)) if label[i] != ' '])

        if label == '':
            messagebox.showwarning("Error", "Key must have a label")
            return
        if label in list(Key_Store.public_keys):
            if label in list(Key_Store.private_keys):
                answer = messagebox.askokcancel(
                    "Warning", "Private Key with that label already exists.\nContinuing will overwrite the old key.")
                if answer:
                     pass
                else:
                    return
            else:
                answer = messagebox.askokcancel(
                    "Warning", "Public Key with that label already exists.\nContinuing will overwrite the old key.")
                if answer:
                    pass
                else:
                    return

        if type(key) == Private_Key:
            Key_Store.private_keys[label] = key
            Key_Store.public_keys[label] = key.pub_key
            update_key_OptionMenu()
            popup.destroy()
            messagebox.showinfo(message = "Corresponding Public Key:\n\n"+str(key.pub_key)+"\n\nshare it with people you want to be able to reveive encrypted messages from")
            Key_Store.write_keys()
        elif type(key) == Public_Key:
            Key_Store.public_keys[label] = key
            update_key_OptionMenu()
            popup.destroy()
            Key_Store.write_keys()
        else:
            messagebox.showwarning("Error", "No valid key entered.")
            return

    popup.bind('<Return>', save)
    ttk.Button(option_frame, text="Save", command=save).grid(
        column=3, row=0, padx=4)


import_btn.btn.configure(command=Import)

def Export():
    popup = tk.Toplevel()
    popup.title('Keys')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)

    popup_width=500
    popup_height=300
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))

    text = 'Public Key(s):\n'
    for key_label in Key_Store.public_keys:
        text += '\n'+str(key_label)+'\n'+str(Key_Store.public_keys[key_label])+'\n'
    text += '\nPrivate Key(s):\n'
    for key_label in Key_Store.private_keys:
        text += '\n'+str(key_label)+'\n'+str(Key_Store.private_keys[key_label])+'\n'

    keys_text = tk.Text(popup, height=100)
    keys_text.insert('1.0', text)
    keys_text["state"] = tk.DISABLED
    keys_text.pack(fill=tk.BOTH)


export_btn.btn.configure(command=Export)


def view_pub_keys():
    text = 'Your Public Key(s):\n'
    for key_label in Key_Store.private_keys:
        text+= '\n'+str(key_label)+'\n'+str(Key_Store.private_keys[key_label].pub_key)+'\n'

    popup = tk.Toplevel()
    popup.title('Public Key(s)')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)

    popup_width=500
    popup_height=300
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))

    keys_text = tk.Text(popup, height=100)
    keys_text.insert('1.0', text)
    keys_text["state"] = tk.DISABLED
    keys_text.pack(fill=tk.BOTH)


def Delete_Key(event=None):
    popup = tk.Toplevel()
    popup.title('Delete Key')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)
    for i in range(2):
        popup.columnconfigure(i, weight=1)

    popup_width=450
    popup_height=180
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)

    var=tk.StringVar()
    ttk.Radiobutton(popup, text='Private Key', var=var, value='Private Key').grid(row=0, column=0, sticky=tk.W, padx=4, pady=2)
    ttk.Radiobutton(popup, text='Public Key', var=var, value='Public Key').grid(row=1, column=0, sticky=tk.W, padx=4, pady=2)

    selected_key = tk.StringVar()
    key_options = ttk.OptionMenu(popup, selected_key, "No Keys")
    key_options.grid(row=2, column=0, columnspan=2, sticky=tk.W+tk.E, padx=6, pady=4)

    key_txt = tk.Text(popup, height=4, state=tk.DISABLED)
    key_txt.grid(row=3, column=0, columnspan=2, sticky=tk.W+tk.E, padx=4)

    def update_delete_key_options(*args):
        key_list = []
        if var.get() == 'Private Key':
            key_list = list(Key_Store.private_keys)
        if var.get() == 'Public Key':
            key_list = list(Key_Store.public_keys)
            for key in list(Key_Store.private_keys):
                if key in key_list:
                    key_list.remove(key)
        if key_list != []:
            key_options["menu"].delete(0, tk.END)
            selected_key.set(key_list[0])
            for key in key_list:
                key_options["menu"].add_command(label=key, command=tk._setit(selected_key, key))
        if key_list == []:
            key_options["menu"].delete(0, tk.END)
            selected_key.set("No Keys")

    var.trace_add('write', update_delete_key_options)

    def update_key_txt(*args):
        key_txt["state"] = tk.NORMAL
        key_txt.delete('1.0', tk.END)
        if var.get() == 'Private Key':
            if selected_key.get() == "No Keys":
                delete_key_btn["state"] = tk.DISABLED
            else:
                key_txt.insert('1.0', Key_Store.private_keys[selected_key.get()])
                delete_key_btn["state"] = tk.NORMAL
        if var.get() == 'Public Key':
            if selected_key.get() == "No Keys":
                delete_key_btn["state"] = tk.DISABLED
            else:
                key_txt.insert('1.0', Key_Store.public_keys[selected_key.get()])
                delete_key_btn["state"] = tk.NORMAL
        key_txt["state"] = tk.DISABLED

    selected_key.trace_add('write', update_key_txt)

    def delete_all_keys():
        answer = messagebox.askokcancel(title="WARNING!", message="WARNING!\nThis will delete all keys, public and private")
        if answer:
            Key_Store.private_keys = {}
            Key_Store.public_keys = {}
            Key_Store.write_keys()
            update_delete_key_options()
            update_key_OptionMenu()
            popup.destroy()

    ttk.Button(popup, text="Delete All Keys", command=delete_all_keys).grid(row=4, column=0)

    def delete_key(event=None):
        key = selected_key.get()
        if var.get() == 'Private Key':
            answer =  messagebox.askokcancel(title="WARNING!", message="WARNING!\nThis will delete the private key:\n"+str(key)+"\nAND it's corresponding public key")
            if answer:
                del Key_Store.public_keys[key]
                del Key_Store.private_keys[key]
                Key_Store.write_keys()
                update_delete_key_options()
                update_key_OptionMenu()
                popup.destroy()
        if var.get() == 'Public Key':
            answer =  messagebox.askokcancel(title="WARNING!", message="WARNING!\nThis will delete the public key:\n"+str(key))
            if answer:
                del Key_Store.public_keys[key]
                Key_Store.write_keys()
                update_delete_key_options()
                update_key_OptionMenu()
                popup.destroy()

    delete_key_btn = ttk.Button(popup, text="Delete Key", command=delete_key)
    delete_key_btn["state"] = tk.DISABLED
    delete_key_btn.grid(row=4, column=1)
    popup.bind('<Return>', delete_key)

def set_theme(*args):
    theme = main_window.theme_var.get()
    main_window.style.theme_use(theme)

main_window.theme_var.trace_add('write', set_theme)

def clear(text_input):
    text_input.text.delete('1.0', tk.END)

def clear_Message():
    clear(message_input)

def clear_Ciphertext():
    clear(ciphertext_input)

def clear_Both(event=None):
    clear_Message()
    clear_Ciphertext()

def close_popup(event=None):
    pass
        

def set_password():
    popup = tk.Toplevel(main_window.root)
    popup.title('Set password')
    def destroy_popup(event=None):
        main_window.root.destroy()
    popup.protocol("WM_DELETE_WINDOW", destroy_popup)
    popup.bind('<Command-Key-w>', destroy_popup)

    popup_width=400
    popup_height=160
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)

    password_frame = ttk.LabelFrame(popup, text='Password')
    password_frame.pack(fill=tk.BOTH, padx=4)
    password_var = tk.StringVar()
    password_entry = tk.Entry(password_frame, textvariable=password_var, show="*")
    password_entry.pack(fill=tk.BOTH)
    password_entry.focus_set()

    re_enter_frame = ttk.LabelFrame(popup, text='Re-enter Password')
    re_enter_frame.pack(fill=tk.BOTH, padx=4)
    re_enter_var = tk.StringVar()
    tk.Entry(re_enter_frame, textvariable=re_enter_var, show="*").pack(fill=tk.BOTH)

    min_password_len = 6

    password_message = tk.StringVar()
    password_message.set('password must be at least '+str(min_password_len)+' characters')
    password_message_label = ttk.Label(popup, text=password_message.get())
    password_message_label.config(foreground='red')
    password_message_label.pack()

    def save(event=None):
        if password_var.get() != '' and len(password_var.get()) >= min_password_len and password_var.get() == re_enter_var.get():
            Key_Store.password = password_var.get()
            Key_Store.password_pub_key = password_priv_key(password_var.get()).pub_key
            popup.destroy()
            main_window.root.deiconify()
            Key_Store.write_keys()

    popup.bind('<Return>', save)
    save_btn = ttk.Button(popup, text="Save", command=save)
    save_btn.pack()
    save_btn["state"] = tk.DISABLED

    def check_match(*args):
        if password_var.get() != '' and len(password_var.get()) >= min_password_len and password_var.get() == re_enter_var.get():
            save_btn["state"] = tk.NORMAL
            password_message.set('password: OK')
            password_message_label.config(text=password_message.get(), foreground='green')
        else:
            save_btn["state"] = tk.DISABLED
            if len(password_var.get()) < min_password_len:
                password_message.set('password must be at least '+str(min_password_len)+' characters')
            elif password_var.get() != re_enter_var.get():
                password_message.set('passwords do not match')
            password_message_label.config(text=password_message.get(), foreground='red')

    password_var.trace_add('write', check_match)
    re_enter_var.trace_add('write', check_match)

def enter_password():
    popup = tk.Toplevel(main_window.root)
    popup.title('Enter password')
    def destroy_popup(event=None):
        main_window.root.destroy()
    popup.protocol("WM_DELETE_WINDOW", destroy_popup)
    popup.bind('<Command-Key-w>', destroy_popup)

    popup_width=400
    popup_height=90
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)

    password_frame = ttk.LabelFrame(popup, text='Password')
    password_frame.pack(fill=tk.BOTH, padx=4)
    password_var = tk.StringVar()
    password_entry = tk.Entry(password_frame, textvariable=password_var, show="*")
    password_entry.pack(fill=tk.BOTH)
    password_entry.focus_set()
    
    button_frame = ttk.Frame(popup)
    button_frame.pack(fill=tk.BOTH, pady=2)
    for i in range(2):
        button_frame.columnconfigure(i, weight=1)
    
    def unlock(event=None):
        Key_Store.password = password_var.get()
        try:
            Key_Store.read_keys()
            update_key_OptionMenu()
            popup.destroy()
            main_window.root.deiconify()
        except:
            messagebox.showwarning(message="Incorrect password!")
            Key_Store.password = None
            password_var.set('')

    popup.bind('<Return>', unlock)
    unlock_btn = ttk.Button(button_frame, text="Unlock", command=unlock)
    unlock_btn.grid(row=0, column=1)
    
    def reset():
        messagebox.showwarning(message="There is no way to recover your password encrypted keys!")
        answer = messagebox.askokcancel(message="WARNING!\nReset password?\nall keys will be lost")
        if answer:
            popup.destroy()
            remove(Key_Store.key_file)
            Key_Store.public_keys = Key_Store.private_keys = {}
            Key_Store.password = Key_Store.password_pub_key = None
            update_key_OptionMenu()
            set_password()
        
    
    unlock_btn = ttk.Button(button_frame, text="Forgot password", command=reset)
    unlock_btn.grid(row=0, column=0)
    
def change_password():
    if  Key_Store.password == None:
            messagebox.showwarning(message="Unlock app first")
            return
    popup = tk.Toplevel(main_window.root)
    popup.title('Change password')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)

    popup_width=400
    popup_height=210
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)

    old_password_frame = ttk.LabelFrame(popup, text='Old password')
    old_password_frame.pack(fill=tk.BOTH, padx=4)
    old_password_var = tk.StringVar()
    old_password_frame_entry = tk.Entry(old_password_frame, textvariable=old_password_var, show="*")
    old_password_frame_entry.pack(fill=tk.BOTH)
    old_password_frame_entry.focus_set()

    new_password_frame = ttk.LabelFrame(popup, text='New password')
    new_password_frame.pack(fill=tk.BOTH, padx=4)
    new_password_var = tk.StringVar()
    tk.Entry(new_password_frame, textvariable=new_password_var, show="*").pack(fill=tk.BOTH)

    re_enter_frame = ttk.LabelFrame(popup, text='Re-enter new password')
    re_enter_frame.pack(fill=tk.BOTH, padx=4)
    re_enter_var = tk.StringVar()
    tk.Entry(re_enter_frame, textvariable=re_enter_var, show="*").pack(fill=tk.BOTH)
    
    min_password_len = 6
    
    password_message = tk.StringVar()
    password_message.set('password must be at least '+str(min_password_len)+' characters')
    password_message_label = ttk.Label(popup, text=password_message.get())
    password_message_label.config(foreground='red')
    password_message_label.pack()
    
    def save(event=None):
        if new_password_var.get() != '' and len(new_password_var.get()) >= min_password_len and new_password_var.get() == re_enter_var.get() and old_password_var.get() == Key_Store.password:
            Key_Store.password = new_password_var.get()
            Key_Store.password_pub_key = password_priv_key(new_password_var.get()).pub_key
            popup.destroy()
            Key_Store.write_keys()
            Key_Store.read_keys()
            update_key_OptionMenu()
            main_window.root.deiconify()
        
        elif old_password_var.get() != Key_Store.password:
            messagebox.showwarning(message="Incorrect password")

    popup.bind('<Return>', save)
    save_btn = ttk.Button(popup, text="Save", command=save)
    save_btn.pack()
    save_btn["state"] = tk.DISABLED

    def check_match(*args):
        if new_password_var.get() != '' and len(new_password_var.get()) >= min_password_len and new_password_var.get() == re_enter_var.get():
            save_btn["state"] = tk.NORMAL
            password_message.set('password: OK')
            password_message_label.config(text=password_message.get(), foreground='green')
        else:
            save_btn["state"] = tk.DISABLED
            if len(new_password_var.get()) < min_password_len:
                password_message.set('password must be at least '+str(min_password_len)+' characters')
            elif new_password_var.get() != re_enter_var.get():
                password_message.set('passwords do not match')
            password_message_label.config(text=password_message.get(), foreground='red')

    new_password_var.trace_add('write', check_match)
    re_enter_var.trace_add('write', check_match)
    
    
def reset():
    messagebox.showwarning(message="This will delete all saved keys and reset your password")
    answer = messagebox.askokcancel(message="WARNING!\nReset password?\nall keys will be lost")
    if answer:
        main_window.root.withdraw()
        remove(Key_Store.key_file)
        Key_Store.public_keys = Key_Store.private_keys = {}
        Key_Store.password = Key_Store.password_pub_key = None
        update_key_OptionMenu()
        set_password()

########
# Menu #
########

menu = tk.Menu(main_window.root, tearoff=0)
main_window.root.configure(menu=menu)

keys_menu = tk.Menu(menu, tearoff=0)
keys_menu.add_command(label='View public keys', command=view_pub_keys)
keys_menu.add_command(label='New key', command= lambda: Import('event'), accelerator="Command+N")
keys_menu.add_command(label='Delete key', command=Delete_Key, accelerator="Command+D")
keys_menu.add_command(label='Save key(s)', command=Key_Store.write_keys, accelerator="Command+s")
menu.add_cascade(label='Keys', menu=keys_menu)

view_menu = tk.Menu(menu, tearoff=0)
theme_menu = tk.Menu(menu, tearoff=0)
for theme in main_window.style.theme_names():
    theme_menu.add_radiobutton(label=theme, value=theme, variable=main_window.theme_var)
view_menu.add_cascade(label='Theme', menu=theme_menu)
view_menu.add_command(label="Close popup", accelerator = "command+W", command=close_popup)
menu.add_cascade(label='View', menu=view_menu)

clear_menu = tk.Menu(menu, tearoff=0)
clear_menu.add_command(label="Clear Message", command=clear_Message)
clear_menu.add_command(label="Clear Ciphertext", command=clear_Ciphertext)
clear_menu.add_command(label="Clear All", command=clear_Both, accelerator="command+BackSpace")
menu.add_cascade(label='Clear', menu=clear_menu)

option_menu = tk.Menu(menu, tearoff=0)
option_menu.add_command(label="Change password", command=change_password)
option_menu.add_command(label="Reset", command=reset)
menu.add_cascade(label='Options', menu=option_menu)

#########
# Binds #
#########

main_window.root.bind_all('<Command-Key-d>', Delete_Key)
main_window.root.bind_all('<Command-Key-n>', Import)
main_window.root.bind_all('<Command-Key-BackSpace>', clear_Both)
main_window.root.bind_all('<Command-Key-s>', Key_Store.write_keys)
main_window.root.bind_all('<Command-Key-q>', main_window.root.destroy)
main_window.root.bind_all('<Command-Key-w>', close_popup)

#################
# Launching GUI #
#################

def launch_GUI():
    try:
        with open(Key_Store.key_file, 'x') as f:
            f.close()
            pass
        set_password()
    except:
        with open(Key_Store.key_file, 'r') as f:
            if 'ciphertext' not in f.read():
                set_password()
            else:
                enter_password()
            f.close()
            pass
    update_key_OptionMenu()
    main_window.root.mainloop()
    # Exiting GUI
    Key_Store.write_keys()
    objects = list(globals())
    for obj in objects:
        if not obj.startswith("__"):
            del globals()[obj]
    del obj, objects


if launch_gui:
    launch_GUI()
