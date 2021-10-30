#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""@author: satsuma.blog ."""

from random import SystemRandom, randint

default_bit_length = 512
base62_alphabet = \
    [str(i) for i in range(10)] + \
    [chr(i) for i in range(97, 123)] + \
    [chr(i) for i in range(65, 91)]


def gcd_ext(a: int, b: int) -> tuple:
    """
    Find the greatest common divisor (gcd) of a and b.

    Parameters
    ----------
    a : int
        Any integer.
    b : int
        Any integer.

    Returns
    -------
    tuple
        (gcd,x,y), x and y integers such that gcd=ax+by..

    """
    if not(a % 1 == 0 and b % 1 == 0):
        print("Need to use integers for gcd.")
        return None
    if a == 0:
        return (abs(b), 0, abs(b)//b)
    else:
        quot = b//a

        gcd, x, y = gcd_ext(b % a, a)
        return (gcd, y - quot * x, x)


def modular_inverse(a: int, b: int) -> int:
    """
    Multiplicative inverse of a modulo b. Returns none if gcd(a,b) != 1.

    Parameters
    ----------
    a : int
        An integer you want to find the inverse of modulo b.
    b : int
        See modular arithmetic for more information.

    Returns
    -------
    int
        An integer, n such that a*n = 1 (mod b). If a and b are not co-prime, a
        has no multiplicative inverse modulo b..

    """
    (g, x, y) = gcd_ext(a, b)
    if not g == 1:
        print('The numbers are not comprime')
        return None
    x = x % b
    return x


def miller_rabin(p: int, a: int) -> bool:
    """
    Test whether a number is prime using the Miller–Rabin primality test.

    Parameters
    ----------
    p : int
        Number being tested.
    a : int
        Witness.

    Returns
    -------
    bool
        True if prime, False if not.

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
        This function uses miller_rabin which is a probabilistic primality
        test, with 50 random witnesses the probability that a composite number
        is incorrectly identified as prime is less than 10**(-30).
        The default is 50.

    Returns
    -------
    bool
        True if p is prime, False if not.

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
        e.g. a 512 bit prime is between 2**511 and 2**512.
        The default is default_bit_length.

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


def decimal_to_base(number: int, alphabet: list = base62_alphabet) -> str:
    """
    Convert an integer to a string representation of any base.

    Parameters
    ----------
    number : int
        The number you want to convert.
    alphabet : list, optional
        A list of symbols to be used in the base "length of alphabet"
        representation of the number. The default is base62_alphabet.

    Returns
    -------
    str
        A string representing the number in the given base.

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
    length = len(base_list)
    for j in range(length):
        x = pow(base, length-j-1)
        base_list[j] = alphabet[number//x]
        number -= alphabet.index(base_list[j])*x
    base_string = ''.join(base_list)
    return base_string


def base_to_decimal(base_string: str, alphabet: list = base62_alphabet) -> int:
    """
    Reverse of decimal_to_base.

    Parameters
    ----------
    base_string : str
        The output of decimal_to_base.
    alphabet : list, optional
        DESCRIPTION. The default is base62_alphabet.

    Returns
    -------
    int
        DESCRIPTION.

    """
    decimal = 0
    base = len(alphabet)
    for i in range(1, len(base_string)+1):
        decimal += alphabet.index(base_string[-i])*pow(base, i-1)
    return decimal
