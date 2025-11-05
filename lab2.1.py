import secrets
from typing import Tuple
import math


def bm_generator_bytes(p: int, a: int, n: int, state=None) -> Tuple[bytes, int]:
    if state is None:
        state = secrets.randbelow(p - 1) + 1

    out_bytes = bytearray()
    for _ in range(n):
        k = (state * 256) // (p - 1)
        out_bytes.append(k)
        state = pow(a, state, p)
    return bytes(out_bytes), state

BM_P = int("CEA42B987C44FA642D80AD9F51F10457690DEF10C83D0BC1BCEE12FC3B6093E3", 16)
BM_A = int("5B88C41246790891C095E2878880342E88C79974303BD0400B090FE38A688356", 16)


def bytes_to_number(byte_list):
    result = 0
    for b in byte_list:
        result = (result << 8) + b
    return result


def int_to_hex(dec_tuple: tuple) -> tuple:
    return tuple(format(x, 'x') for x in dec_tuple)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def trial_division_status(n):
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for p in small_primes:
        if n == p:
            return "prime"
        if n % p == 0:
            return "composite"
    return "passes"


def miller_rabin(n: int, k: int, state: int) -> Tuple[bool, int]:
    if n < 2:
        return False, state
    if n in (2, 3):
        return True, state
    if n % 2 == 0:
        return False, state
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        rnd_bytes, state = bm_generator_bytes(BM_P, BM_A, 8, state)
        a = bytes_to_number(rnd_bytes) % (n - 4) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False, state
    return True, state


def generate_random_prime(bits: int, k=20, state=None) -> Tuple[int, int]:
    if bits < 8:
        raise ValueError("bits має бути >= 8")
    while True:
        byte_count = (bits + 7) // 8
        rnd_bytes, state = bm_generator_bytes(BM_P, BM_A, byte_count, state)
        candidate = bytes_to_number(rnd_bytes)
        candidate |= (1 << (bits - 1))
        candidate |= 1

        status = trial_division_status(candidate)
        if status == "prime":
            return candidate, state
        if status == "composite":
            continue

        is_prob, state = miller_rabin(candidate, k, state)
        if is_prob:
            return candidate, state


def modinv(a, m):
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r > 1:
        raise ValueError("Обернений елемент не існує")
    if t < 0:
        t += m
    return t


def generate_rsa_keys(bits=256, state=None):
    p, state = generate_random_prime(bits, state=state)
    q, state = generate_random_prime(bits, state=state)
    while p == q:
        q, state = generate_random_prime(bits, state=state)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (n, e), (d, p, q), state


def GenerateKeyPair(bits=256, state=None):
    public_A, private_A, state = generate_rsa_keys(bits, state)
    public_B, private_B, state = generate_rsa_keys(bits, state)

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


if __name__ == "__main__":
    keys = GenerateKeyPair(256)
    print("Відкритий ключ A (n, e):", keys[0])
    print("Секретний ключ A (d, p, q):", keys[1])
    print()
    print("Відкритий ключ B (n, e):", keys[2])
    print("Секретний ключ B (d, p, q):", keys[3])

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