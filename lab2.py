import random
import secrets
from typing import Tuple

def LehmerLow(x0, count):
    m = 2**32
    a = 2**16 + 1
    c = 119
    if x0 == 0:
        raise ValueError("Початкове значення не повинно дорівнювати 0")
    x = x0
    result = []
    for _ in range(count):
        x = (a * x + c) % m
        result.append(x & 0xFF)
    return result, x


def bytes_to_number(bytes_list):
    result = 0
    for byte in bytes_list:
        result = (result << 8) + int(byte)
    return result

def int_to_hex(dec_tuple: tuple) -> tuple:
    return tuple(format(x, 'x') for x in dec_tuple)

def jacobi_symbol(a, b):
    if b <= 0 or b % 2 == 0:
        raise ValueError("b має бути додатним непарним цілим числом")
    a = a % b
    result = 1

    while a != 0:
        while a % 2 == 0:
            a //= 2
            if b % 8 in (3, 5):
                result = -result

        a, b = b, a
        if a % 4 == 3 and b % 4 == 3:
            result = -result

        a %= b

    if b == 1:
        return result
    else:
        return 0


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def trial_division(n):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True


def solovay_strassen(p, k, initial_value):

    if p < 2:
        return False, initial_value
    if p == 2:
        return True, initial_value
    if p % 2 == 0:
        return False, initial_value

    for _ in range(k):
        bts, initial_value = LehmerLow(initial_value, 4)
        a = bytes_to_number(bts) % (p - 3) + 2
        g = gcd(a, p)
        if g > 1:
            return False, initial_value
        j_s = jacobi_symbol(a, p)
        if j_s == -1:
            j_s = p - 1
        d = pow(a, (p - 1) // 2, p)
        if d != j_s:
            return False, initial_value
    return True, initial_value


def find_random_prime(n0, n1, k=10, initial_value=39, max_tries=10000):
    if n0 < 3:
        n0 = 3
    if n0 % 2 == 0:
        n0 += 1

    tries = 0
    while True:
        tries += 1
        if tries > max_tries:
            raise RuntimeError("Занадто багато спроб")

        bts, initial_value = LehmerLow(initial_value, 4)
        x = bytes_to_number(bts) % (n1 - n0 + 1) + n0

        m0 = x if x % 2 == 1 else x + 1
        m = m0
        while m <= n1:
            td = trial_division(m)
            if td:
                return m, initial_value
            is_prob, initial_value = solovay_strassen(m, k, initial_value)
            if is_prob:
                return m, initial_value
            m += 2


def find_cute_prime(n0, n1, k=10, initial_value=39, max_i=32):
    p_prime, initial_value = find_random_prime(n0, n1, k, initial_value)
    for i in range(1, max_i + 1):
        p = (1 << i) * p_prime + 1
        if not trial_division(p):
            is_prob, initial_value = solovay_strassen(p, k, initial_value)
        else:
            is_prob = True
        if is_prob:
            return p, initial_value
    return None, initial_value


def modinv(a, m):

    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r > 1:
        raise ValueError("Обернений елемент не існує")
    if t < 0:
        t += m
    return t


def generate_rsa_keys(bit_length=256, initial_value=12345):
    n0 = 2**(bit_length - 1)
    n1 = 2**bit_length - 1

    p, initial_value = find_cute_prime(
        n0, n1, k=20, initial_value=initial_value)
    q, initial_value = find_cute_prime(
        n0, n1, k=20, initial_value=initial_value)

    if p == q:
        q, initial_value = find_cute_prime(
            n0, n1, k=20, initial_value=initial_value + 1)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)
    return (n, e), (d, p, q), initial_value


def GenerateKeyPair(bit_length=256, initial_value=11111):
    public_A, private_A, initial_value = generate_rsa_keys(
        bit_length, initial_value)
    public_B, private_B, initial_value = generate_rsa_keys(
        bit_length, initial_value)
    nA, _ = public_A
    nB, _ = public_B
    if nA > nB:
        public_A, public_B = public_B, public_A
        private_A, private_B = private_B, private_A
    return [
        int_to_hex(public_A),
        int_to_hex(private_A),
        int_to_hex(public_B),
        int_to_hex(private_B)
    ]


p, initial_value = find_cute_prime(
    2**255, 2**256 - 1, k=20, initial_value=12343)
print()
keys = GenerateKeyPair(256, 12345)
print("Відкритий ключ A:", keys[0])
print("Секретний ключ A:", keys[1])
print()
print("Відкритий ключ B:", keys[2])
print("Секретний ключ B:", keys[3])


if __name__ == "__main__":
    p, initial_value = find_cute_prime(
        2 ** 255, 2 ** 256 - 1, k=20, initial_value=12343)
    keys = GenerateKeyPair(256, 12345)

    with open('PublicKeysA.txt', 'wt') as f:
        f.write(str(keys[0][1] + "," + keys[0][0]))

    with open('SecretKeysA.txt', 'wt') as f:
        f.write(str(keys[1][0] + "," + keys[1][1] + "," + keys[1][2]))

    with open('PublicKeysB.txt', 'wt') as f:
        f.write(str(keys[2][1] + "," + keys[2][0]))

    with open('SecretKeysB.txt', 'wt') as f:
        f.write(str(keys[3][0] + "," + keys[3][1] + "," + keys[3][2]))

    print("Відкритий ключ A збережено у 'PublicKeysA.txt'.")
    print("Секретний ключ A збережено у 'SecretKeysA.txt'.")
    print("Відкритий ключ B збережено у 'PublicKeysB.txt'.")
    print("Секретний ключ B збережено у 'SecretKeysB.txt'.")

