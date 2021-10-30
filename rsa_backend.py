#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""@author: satsuma.blog ."""
##############
# To Do List #
##############
# Add a message when decrypting with the wrong key

from number_theory_functions import (default_bit_length, base62_alphabet,
                                     modular_inverse, is_prime, random_prime,
                                     decimal_to_base, base_to_decimal)
from hashlib import sha3_256
from os import path, remove

default_exponent = 65537


class Message:
    """Represents a message to be signed, encrypted and sent."""

    start_of_signatures_message = \
        '\n\n----------------------SIGNATURES----------------------\n'
    separator = '_'
    allowed_characters = base62_alphabet + \
        [' ', '.', chr(10), ',', "'", '"', '`', '!', '?', ':', ';', '(', ')',
         '[', ']', '{', '}', '/', '|', '\\', '-', '_', '@', '%', '&', '#', '~',
         '=', '+', '*', '<', '>', '^', '$', '€', '£']

    def __init__(self, string: str):
        unsupported_chars = ''.join(list(dict.fromkeys(
            [char for char in string if char not in Message.allowed_characters]
            )))
        if unsupported_chars != '':
            print(
                '\nWARNING: message contains unsupported character(s): '
                + unsupported_chars)
        self.string = string
        self.signatures = {}
        if Message.start_of_signatures_message in string:
            self.string = string[
                :string.index(Message.start_of_signatures_message)]
            signatures_string = string[
                string.index(Message.start_of_signatures_message)
                + len(Message.start_of_signatures_message):]
            labels_list = [i for i in range(len(signatures_string))
                           if signatures_string[i] == ':']
            other_list = [signatures_string[labels_list[j]+2:labels_list[j+1]]
                          for j in range(len(labels_list)-1)] \
                + [signatures_string[labels_list[-1]+2:]]
            for i in range(len(other_list)//2):
                self.signatures[str(import_key(other_list[i*2]))] = \
                    base_to_decimal(other_list[i*2+1][
                        :other_list[i*2+1].index("\n")])
        self.h = int(sha3_256(self.string.encode()).hexdigest(), 16)

    def __str__(self):
        text_string = self.string
        if self.signatures != {}:
            text_string += Message.start_of_signatures_message
            for pub_key in self.signatures:
                text_string += '\nPUBLIC KEY:\n' + pub_key + '\nSIGNATURE:\n' \
                    + decimal_to_base(self.signatures[pub_key]) + '\n'
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
                key = import_key(pub_key)
                if self.h == pow(self.signatures[pub_key], key.e, key.N):
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
                txt += 'WARNING! \nInvalid signature(s) from:\n' +\
                    '\n'.join(invalid_sigs)
            if valid_sigs != []:
                if txt != '':
                    txt += '\n'
                txt += 'Valid signature(s) from:\n' + '\n'.join(valid_sigs)
        return txt


class Key:
    """Represents a generic key."""

    def __str__(self):
        string = self.prefix + Message.separator
        for i in range(2):
            string += decimal_to_base(list(self.__dict__.values())
                                      [i]) + Message.separator
        return string


class Private_Key(Key):
    """Represents a private key."""
    prefix = 'privkey'

    def __init__(self, p: int = None, q: int = None,
                 Bit_Length: int = default_bit_length):
        self.p = p
        self.q = q
        if p is None or q is None:
            print('\nGenerating two random ' + str(Bit_Length) +
                  ' bit primes to form a new private key...')
            self.p = random_prime(Bit_Length)
            self.q = random_prime(Bit_Length)
        self.pub_key = Public_Key(self.p*self.q)
        self.d = modular_inverse(
            self.pub_key.e, (self.pub_key.N - self.p - self.q + 1))

    def decrypt(self, ciphertext: str) -> Message:
        cipher_list = de_format(ciphertext)
        sub_message_decimal_list = [str(pow(c, self.d, self.pub_key.N))[
            1:] for c in cipher_list]
        sub_message_list = [[
            Message.allowed_characters[int(decimal[2*i:2*i+2])]
            for i in range(len(decimal)//2)]
            for decimal in sub_message_decimal_list]
        return Message(''.join([''.join(sub_message)
                                for sub_message in sub_message_list]))

    def sign(self, message: Message) -> dict:
        message.signatures[str(self.pub_key)] = pow(
            message.h, self.d, self.pub_key.N)
        return message.signatures


class Public_Key(Key):
    """Represents a public key."""
    prefix = 'pubkey'

    def __init__(self, N: int, e: int = default_exponent):
        self.N = N
        self.e = e

    def encrypt(self, message: Message) -> str:
        sub_message_chr_length = int((len(bin(self.N)[2:])/2)*0.3)
        text_string = str(message)
        number_of_sub_messages = len(text_string)//sub_message_chr_length
        sub_message_list = [text_string[i*sub_message_chr_length:
                                        (i+1)*sub_message_chr_length]
                            for i in range(number_of_sub_messages)] +\
            [text_string[number_of_sub_messages*sub_message_chr_length:]]
        decimal_list = [['%.2d' % Message.allowed_characters.index(
            char) for char in sub_message] for sub_message in sub_message_list]
        encrypted_list = [pow(int('1' + ''.join(i)), self.e, self.N)
                          for i in decimal_list]
        return 'ciphertext' + Message.separator +\
            Message.separator.join([decimal_to_base(i)
                                    for i in encrypted_list]) +\
            Message.separator


def de_format(any_string: str) -> list:
    separators = [i for i in range(len(any_string))
                  if any_string[i] == Message.separator]
    de_formatted = [base_to_decimal(
        any_string[separators[i]+1:separators[i+1]])
        for i in range(len(separators)-1)]
    return de_formatted


def import_key(string: str):
    if string[:len(Private_Key.prefix)] == Private_Key.prefix:
        p, q = de_format(string)
        return Private_Key(p, q)

    if string[:len(Public_Key.prefix)] == Public_Key.prefix:
        N, e = de_format(string)
        return Public_Key(N, e)

    print("ERROR: No valid key!")
    return None


def password_key(password: str, pub_key: Public_Key = None) -> Private_Key:
    password_bit_length = 1024
    password_hash = bin(int(sha3_256(password.encode()).hexdigest(), 16))[2:]
    while len(password_hash) < password_bit_length:
        num_bits_add = password_bit_length - len(password_hash)
        if num_bits_add < 256:
            password_hash += bin(int(
                sha3_256(password_hash.encode()).hexdigest(),
                16))[2:num_bits_add+2]
        else:
            password_hash += bin(int(
                sha3_256(password_hash.encode()).hexdigest(),
                16))[2:]
    password_hash = int(password_hash, 2)

    p = password_hash
    while True:
        if is_prime(p):
            break
        p += 1
    if pub_key is None:
        q = random_prime(password_bit_length)
        priv_key = Private_Key(p, q)
    else:
        q = pub_key.N//p
        priv_key = Private_Key(p, q)
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
    assert Alice_Key.p*Alice_Key.q == Alice_Key.pub_key.N
    assert Bob_Key.p*Bob_Key.q == Bob_Key.pub_key.N
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
    ciphertext1 = import_key(str(Bob_Key.pub_key)).encrypt(Alice_message)
    print('\n'+ciphertext1)
    print('\nBob decrypts this using his private key.\n')
    decrypted_message1 = Bob_Key.decrypt(ciphertext1)
    assert decrypted_message1.string == string
    assert str(Alice_message) == str(decrypted_message1)
    print(decrypted_message1)
    print("""Bob decides to edit the message and then sign the message as well
          as then sending it back to Alice.\n""")
    new_message = Message('Bob is awesome! ' + str(decrypted_message1))
    Bob_Key.sign(new_message)
    print(new_message)
    ciphertext2 = import_key(str(Alice_Key.pub_key)).encrypt(new_message)
    print(ciphertext2)
    print("""\nAlice decrypts the message, noticing that her signature is no
longer valid as Bob edited the message.\n""")
    decrypted_message2 = Alice_Key.decrypt(ciphertext2)
    print(decrypted_message2)
    print(decrypted_message2.verify())


class Key_Store:
    private_keys = {}
    public_keys = {}
    password = None
    password_pub_key = None
    key_file = path.join(path.dirname(path.realpath(__file__)), 'keys.txt')
    min_password_len = 6

    def read_keys(self=None, event=None):
        with open(Key_Store.key_file, 'r') as f:
            raw_list = f.readlines()
            f.close()
            pass
        Key_Store.password_pub_key = import_key(raw_list[0])
        keys_ciphertext = raw_list[1]
        keys_message = password_key(
            Key_Store.password,
            Key_Store.password_pub_key).decrypt(keys_ciphertext)
        if 'Valid signature(s) from:\n'+str(Key_Store.password_pub_key) \
                in keys_message.verify():
            print('\nkeys.txt has not been tampered with')
            decrypted_list = str(keys_message).split()
            decrypted_keys_list = decrypted_list[
                :decrypted_list.index(
                    Message.start_of_signatures_message.strip())]
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
            Key_Store.public_keys[key_label] =\
                Key_Store.private_keys[key_label].pub_key

    def write_keys(self=None, event=None):
        try:
            open(Key_Store.key_file, 'x')
        except:
            pass
        if Key_Store.password_pub_key is None:
            print('\nERROR! Failed to write. No Key_Store.password_pub_key')
            return
        text = ''
        remove(Key_Store.key_file)
        for key_label in Key_Store.public_keys:
            if key_label not in Key_Store.private_keys:
                text += str(key_label)+'\n'+str(
                    Key_Store.public_keys[key_label])+'\n'

        for key_label in Key_Store.private_keys:
            text += str(key_label)+'\n'+str(
                Key_Store.private_keys[key_label])+'\n'
        keys_message = Message(text)
        password_key(Key_Store.password,
                     Key_Store.password_pub_key).sign(keys_message)
        keys_ciphertext = Key_Store.password_pub_key.encrypt(keys_message)
        with open(Key_Store.key_file, 'w') as f:
            f.write(str(Key_Store.password_pub_key)+'\n'+keys_ciphertext)
            f.close()
            pass
