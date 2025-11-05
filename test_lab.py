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
    sign_hex = Sign(int_to_hex(k), sender_secrt_d, sender_n)
    signature_hex = pow(hex_to_int(sign_hex), e_rec, n_rec)
    return cipher_hex, int_to_hex(signature_hex)


def ReceiveKey(cipher_hex: str, signature_hex: str, sender_publ_keys: Tuple[int,int], receiver_secrt_d: int, receiver_n: int) -> Tuple[str, bool]:
    k_hex = Decrypt(cipher_hex, receiver_secrt_d, receiver_n)
    sign_hex = Decrypt(signature_hex, receiver_secrt_d, receiver_n)
    e_sender, n_sender = sender_publ_keys
    signature_valid = Verify(k_hex, sign_hex, e_sender, n_sender)
    return k_hex, signature_valid


if __name__ == '__main__':
    e_A = "10001"
    n_A = "66cc60f4f3cd3eacaaa4fa9c48edb24f4eeb04a4723af1129a35034d40e3fd3a8715cde0d728ce12ad692d0353efee7f273dfc10686505c6ee7d863d8a9cbf11"
    d_A = "51da7b799087e557e7a8e6447b6d8985ccf926012b53f3913468f1f019b370769f85d2501fd02c1581b8034a099a83183c6c207d7a21653964a692c92ea6a3e1"

    e_B = "10001"
    n_B = "9340367DEA7702D25DF43F8E31E708910BD2679C3387FFB7B56A35FF5A1624B62FDCA07A7399F675CB36E9E23408BF7082B8EBAF3D0819211C55887E1E29874F"

    print("Публічний ключ Аліси:", n_A)
    print("Секретний ключ Аліси:", d_A)
    print("Публічний ключ Боба:", n_B)

    e_A = hex_to_int(e_A)
    n_A = hex_to_int(n_A)
    d_A = hex_to_int(d_A)

    e_B = hex_to_int(e_B)
    n_B = hex_to_int(n_B)

    M_hex_A = "0ABAB1234321BABA"
    print('\nПовідомлення від Аліси:', M_hex_A)

    c_for_B_hex = Encrypt(M_hex_A, (e_B, n_B))
    print('Шифротекст для Боба:', c_for_B_hex)

    M_hex_B = "ABC"
    print('\nПовідовлення від Боба:', M_hex_B)

    c_for_A_hex = "4473ECA56E64B6E131E69D75C1A10A50BE8B615E0BCE64199EABD3BABD78866E7D26E2C93FF771A4ED5476152D6CA3CD0B59D38FB7992B83CFFE63733F2713BE"
    print('Шифротекст для Аліси:', c_for_A_hex)

    dec_A = Decrypt(c_for_A_hex, d_A, n_A)
    print('Аліса розшифрувала повідомлення Боба :', dec_A)

    signature_A_hex = Sign(M_hex_A, d_A, n_A)
    print("\nПідпис Аліси", signature_A_hex)

    signature_B_hex = "0A72A83F3717281FCE737EAC9C5B431A36D9C44CC444164335329037F2029C45015676DB9B4030066580D7213E1897A69BFD7244DFEA17AF46C165B61A6C7892"
    print("\nПідпис Боба", signature_B_hex)
    sig_ok_B = Verify(M_hex_B, signature_B_hex, e_B, n_B)
    print('Перевірка підпису від Боба:', sig_ok_B)

    k_hex = "AAABBBCCCDDDEEEFFF0123456789"
    print('\nВипадковий ключ k для розсилки від Аліси:', k_hex)

    key_A, signature_A = SendKey(hex_to_int(k_hex), (e_B, n_B), d_A, n_A)
    print('Зашифрований випадковий ключ від Аліси:', key_A)
    print('Підпис від Аліси:', signature_A)

    key_B = "11F2DD466BA371C39F59CE4A84F9CA1727A9DCF5236A779ACA81021554E9AA16A7C2BF41912393DE04ABAB5DF7BE62EF2F9F83ECDBEC2CEB83179C291124022D"
    signature_B = "21BFE1ADCC0FB9AC601BEA174A2F79B8DEDAD53446FA5D36580905E8B3246D4BC4E11D191A6599D0A407D3F1C3BE185414D7DF041D351384C7C685F0A45F2809"
    print('\nЗашифрований випадковий ключ від Боба:', key_B)
    print('Підпис від Боба:', signature_B)

    key_B_rec, sig_B_valid = ReceiveKey(key_B, signature_B, (e_B, n_B), d_A, n_A)
    print('Отриманий випадковий ключ від Боба:', key_B_rec)
    print('Чи дійсний підпис від Боба і випадковий ключ збігається з відправленим?:', sig_B_valid)