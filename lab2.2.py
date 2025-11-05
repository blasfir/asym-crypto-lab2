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


def SendKey(k: int, receiver_publ_keys: Tuple[int,int], sender_secrt_d: int, sender_n: int) -> Tuple[str, str]:
    e_rec, n_rec = receiver_publ_keys
    if not (0 < k < n_rec):
        raise ValueError("k має задовольняти 0 < k < n_receiver (n_rec)")
    c = pow(k, e_rec, n_rec)
    cipher_hex = int_to_hex(c)
    signature_hex = Sign(int_to_hex(k), sender_secrt_d, sender_n)
    return cipher_hex, signature_hex


def ReceiveKey(cipher_hex: str, signature_hex: str, sender_publ_keys: Tuple[int,int], receiver_secrt_d: int, receiver_n: int) -> Tuple[str, bool]:
    k_hex = Decrypt(cipher_hex, receiver_secrt_d, receiver_n)
    e_sender, n_sender = sender_publ_keys
    signature_valid = Verify(k_hex, signature_hex, e_sender, n_sender)
    return k_hex, signature_valid


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

    M = secrets.randbelow(n_A - 1) + 1
    M_hex = int_to_hex(M)
    print('\nВипадково обране M:', M_hex)

    c_for_A_hex = Encrypt(M_hex, (e_A, n_A))
    c_for_B_hex = Encrypt(M_hex, (e_B, n_B))
    print('\nШифротекст для A:', c_for_A_hex)
    print('Шифротекст для B:', c_for_B_hex)

    dec_A = Decrypt(c_for_A_hex, d_A, n_A)
    dec_B = Decrypt(c_for_B_hex, d_B, n_B)
    print('\nРозшифровано A:', dec_A, '| правильно:', dec_A == M_hex)
    print('Розшифровано B:', dec_B, '| правильно:', dec_B == M_hex)

    signature_A_hex = Sign(M_hex, d_A, n_A)
    sig_ok_A = Verify(M_hex, signature_A_hex, e_A, n_A)
    print('\nПідпис A:', signature_A_hex)
    print('Перевірка підпису A:', sig_ok_A)

    signature_B_hex = Sign(M_hex, d_B, n_B)
    sig_ok_B = Verify(M_hex, signature_B_hex, e_B, n_B)
    print('\nПідпис B:', signature_B_hex)
    print('Перевірка підпису B:', sig_ok_B)

    k = secrets.randbelow(n_A - 1) + 1
    k_hex = int_to_hex(k)
    print('\nВипадковий ключ k для розсилки:', k_hex)

    cipher_hex, signature_hex = SendKey(k, (e_A, n_A), d_B, n_B)
    print('\nВідправлено зашифрований випадковий ключ k:', cipher_hex)
    print('Відправлено підпис:', signature_hex)

    k_rec, sig_valid = ReceiveKey(cipher_hex, signature_hex, (e_B, n_B), d_A, n_A)
    print('\nОтриманий k:', k_rec)
    print('Підпис від B дійсний?:', sig_valid)
    print('k збігається з відправленим?:', k_rec == k_hex)