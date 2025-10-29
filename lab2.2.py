import secrets
import hashlib
import sys
from typing import Tuple

def int_to_hex(i: int) -> str:
    return format(i, 'x')


def hex_to_int(s: str) -> int:
    s = s.strip()
    if s.startswith('0x') or s.startswith('0X'):
        s = s[2:]
    if s == '':
        return 0
    return int(s, 16)


def read_key_pair_from_file(publfile: str, secrtfile: str) -> Tuple[Tuple[int,int], int]:
    with open(publfile, 'r', encoding='utf-8') as f:
        content = f.read().replace(',', ' ').split()
    if len(content) < 2:
        raise ValueError(f"Файл {publfile} повинен містити e та n (hex). Знайдено: {content}")
    e = hex_to_int(content[0])
    n = hex_to_int(content[1])
    with open(secrtfile, 'r', encoding='utf-8') as f:
        keys = f.read().replace(',', ' ').split()
    d = hex_to_int(keys[0])
    p = hex_to_int(keys[1])
    q = hex_to_int(keys[2])

    phi = (p-1)*(q-1)
    ed = (e*d) % phi

    print("ПЕРЕВІРКА:")
    print("p i q =", p, q)
    print("e * d (mod phi(n)) = ", ed)

    return (e, n), d


def Encrypt(message: str, publ_keys: Tuple[int, int]) -> str:
    e, n = publ_keys
    m = hex_to_int(message)
    if not (0 < m < n):
        raise ValueError(f"Повідомлення як число має задовольняти 0 < m < n. m={m}, n={n}")
    c = pow(m, e, n)
    return int_to_hex(c)


def Decrypt(cipher: str, d: int, n: int) -> str:
    c = hex_to_int(cipher)
    m = pow(c, d, n)
    return int_to_hex(m)


def Sign(message: str, d: int, n: int) -> str:
    m = hex_to_int(message)
    s = pow(m, d, n)
    return int_to_hex(s)


def Verify(message: str, sign: str, e: int, n: int) -> bool:
    m = hex_to_int(message)
    s = hex_to_int(sign)
    m_from_sig = pow(s, e, n)
    return (m_from_sig % n) == (m % n)


if __name__ == '__main__':
    try:
        (e_A, n_A), d_A = read_key_pair_from_file('PublicKeysA.txt', 'SecretKeysA.txt')
        (e_B, n_B), d_B = read_key_pair_from_file('PublicKeysB.txt', 'SecretKeysB.txt')
    except FileNotFoundError:
        print('Файли ключів не знайдено. Будь ласка, створіть файли: PublicKeysA.txt, SecretKeysA.txt, PublicKeysB.txt, SecretKeysB.txt у поточній директорії.', file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print('Помилка при читанні ключів:', ex, file=sys.stderr)
        sys.exit(1)

    print('Ключі A (e,n) та d завантажені. Розміри (біти):', n_A.bit_length(), 'і', n_B.bit_length())

    M = secrets.randbelow(n_A - 1) + 1
    M_hex = int_to_hex(M)
    print('\nВипадково обране M:', M_hex)

    c_for_A_hex = Encrypt(M_hex, (e_A, n_A))
    #c_for_B_hex = Encrypt(M_hex, (e_B, n_B))
    print('\nШифротекст для A (hex):', c_for_A_hex)
    #print('Шифротекст для B (hex):', c_for_B_hex)

    dec_A = Decrypt(c_for_A_hex, d_A, n_A)
    #dec_B = Decrypt(c_for_B_hex, d_B, n_B)
    print('\nРозшифровано A:', dec_A, '| правильно:', dec_A == M_hex)
    #print('Розшифровано B:', dec_B, '| правильно:', dec_B == M_hex)

    signature_A_hex = Sign(M_hex, d_A, n_A)
    sig_ok_A = Verify(M_hex, signature_A_hex, e_A, n_A)
    print('\nПідпис A (hex):', signature_A_hex)
    print('Перевірка підпису A:', sig_ok_A)

    #signature_B_hex = Sign(M_hex, d_B, n_B)
    #sig_ok_B = Verify(M_hex, signature_B_hex, e_B, n_B)
    #print('\nПідпис B (hex):', signature_B_hex)
    #print('Перевірка підпису B:', sig_ok_B)