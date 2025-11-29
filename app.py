# app.py
import streamlit as st
import numpy as np
from functools import lru_cache

# --------------------------
# GF(2^8) helpers (AES poly)
# --------------------------
AES_MODULUS = 0x11B  # x^8 + x^4 + x^3 + x + 1
C_AES = 0x63         # 8-bit constant used in paper

def gf_multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a <<= 1
        if hi:
            a ^= AES_MODULUS
        b >>= 1
    return p & 0xFF

def gf_inverse(val):
    if val == 0:
        return 0
    for i in range(1, 256):
        if gf_multiply(val, i) == 1:
            return i
    return 0

# --------------------------
# K-matrices (from paper)
# each row is 8-bit integer (binary in doc)
# --------------------------
K_MATRICES = {
    "4":  [0b00000111, 0b10000011, 0b11000001, 0b11100000,
           0b01110000, 0b00111000, 0b00011100, 0b00001111],
    "44": [0b01010111, 0b10101011, 0b11010101, 0b11101010,
           0b01110101, 0b10111010, 0b01011101, 0b10101110],
    "81": [0b10100001, 0b11010000, 0b01101000, 0b00110100,
           0b00011010, 0b00001101, 0b10000110, 0b01000011],
    "111":[0b11011100, 0b01101110, 0b00110111, 0b10011011,
           0b11001101, 0b11100110, 0b01110011, 0b10111001],
    "128":[0b11111110, 0b01111111, 0b10111111, 0b11011111,
           0b11101111, 0b11110111, 0b11111011, 0b11111101],
}

# --------------------------
# generate S-box from a K matrix + constant (paper method)
# --------------------------
def affine_transform(matrix_rows, byte_val, c=C_AES):
    # matrix_rows: list of 8 integers (each 8-bit row)
    res = 0
    for i in range(8):
        row = matrix_rows[i]
        parity = bin(row & byte_val).count('1') % 2
        res |= (parity << i)
    return res ^ c

@lru_cache(maxsize=8)
def generate_sbox_from_K(k_name):
    """Returns list of 256 ints for S-box for given key (string '4','44', etc.)"""
    K = K_MATRICES[k_name]
    sbox = [0]*256
    for x in range(256):
        inv = gf_inverse(x)
        sbox[x] = affine_transform(K, inv)
    return sbox

def inverse_sbox(sbox):
    inv = [0]*256
    for i,v in enumerate(sbox):
        inv[v] = i
    return inv

# --------------------------
# Crypto ops: substitution cipher (byte-wise)
# --------------------------
def encrypt_bytes_with_sbox(b: bytes, sbox):
    return bytes([sbox[byte] for byte in b])

def decrypt_bytes_with_inv_sbox(enc: bytes, inv_sbox):
    return bytes([inv_sbox[b] for b in enc])

# --------------------------
# Metrics: NL & SAC (ported from user's functions)
# --------------------------
def calculate_nonlinearity(sbox):
    min_nl = 256
    for v in range(1, 256):
        f = []
        for x in range(256):
            val = sbox[x] & v
            parity = bin(val).count('1') % 2
            f.append(1 if parity == 0 else -1)
        fwht = f[:]
        h = 1
        n = 256
        while h < n:
            for i in range(0, n, h*2):
                for j in range(i, i+h):
                    x = fwht[j]
                    y = fwht[j+h]
                    fwht[j] = x + y
                    fwht[j+h] = x - y
            h *= 2
        max_walsh = max(abs(vv) for vv in fwht)
        nl = 128 - (max_walsh / 2)
        if nl < min_nl:
            min_nl = nl
    return int(min_nl)

def calculate_sac(sbox):
    total_sac = 0
    count = 0
    for x in range(256):
        y = sbox[x]
        for j in range(8):
            x_flipped = x ^ (1 << j)
            y_flipped = sbox[x_flipped]
            diff = y ^ y_flipped
            bits_changed = bin(diff).count('1')
            total_sac += bits_changed
            count += 8
    avg_sac = total_sac / count
    # return probability of each output bit flipping given single input bit flip
    return avg_sac / 8

# --------------------------
# Streamlit UI
# --------------------------
st.set_page_config(page_title="Kripto S-box Explorer", layout="centered")
st.title("Kriptografi — S-box Substitution Demo")
st.markdown("Pilih S-box dari paper Alamsyah dkk., input teks, lalu lihat ciphertext & metrik (NL, SAC).")

with st.sidebar:
    st.header("Pengaturan")
    sbox_choice = st.selectbox("Pilih S-box", options=["4","44","81","111","128"], index=1)
    show_metrics = st.checkbox("Tampilkan NL & SAC", value=True)
    encoding = st.selectbox("Encoding input", options=["utf-8","latin-1"], index=0)

st.subheader(f"S-box terpilih: S-box{sbox_choice}")
SBOX = generate_sbox_from_K(sbox_choice)
INV_SBOX = inverse_sbox(SBOX)

st.markdown("### Input")
user_text = st.text_area("Masukkan teks yang mau dienkripsi", value="Hello, Alamsyah!", height=120)

col1, col2 = st.columns(2)
with col1:
    if st.button("Encrypt"):
        try:
            input_bytes = user_text.encode(encoding)
        except Exception as e:
            st.error(f"Encoding error: {e}")
            input_bytes = user_text.encode("utf-8", errors="replace")
        encrypted = encrypt_bytes_with_sbox(input_bytes, SBOX)
        hex_out = " ".join(f"{b:02X}" for b in encrypted)
        st.code(hex_out, language=None)
        st.session_state["last_encrypted"] = encrypted
with col2:
    if st.button("Decrypt (from last encrypted)"):
        if "last_encrypted" not in st.session_state:
            st.warning("Belum ada ciphertext — klik Encrypt dulu.")
        else:
            try:
                dec_bytes = decrypt_bytes_with_inv_sbox(st.session_state["last_encrypted"], INV_SBOX)
                dec_text = dec_bytes.decode(encoding)
            except Exception as e:
                dec_text = dec_bytes.decode("utf-8", errors="replace")
                st.warning("Decode error, mencoba fallback utf-8.")
            st.text_area("Hasil Decrypt", value=dec_text, height=120)

# show last encryption table / verification
if "last_encrypted" in st.session_state:
    st.markdown("### Detail ciphertext (last run)")
    st.write("Bytes (decimal):", list(st.session_state["last_encrypted"]))
    st.write("Bytes (hex):", " ".join(f"{b:02X}" for b in st.session_state["last_encrypted"]))
    # try decrypt to verify
    try:
        dec = decrypt_bytes_with_inv_sbox(st.session_state["last_encrypted"], INV_SBOX)
        st.write("Verified decrypt (utf-8):", dec.decode("utf-8"))
    except Exception:
        st.write("Verified decrypt (latin-1):", dec.decode("latin-1"))

# metrics
if show_metrics:
    with st.expander("Hitung Nonlinearity (NL) & SAC untuk S-box terpilih"):
        st.info("Perhitungan bisa makan waktu beberapa detik.")
        nl = calculate_nonlinearity(SBOX)
        sac = calculate_sac(SBOX)
        st.write(f"Nonlinearity (NL): *{nl}*")
        st.write(f"Strict Avalanche Criterion (SAC): *{sac:.6f}*")

# download S-box mapping
if st.button("Download S-box mapping (JSON)"):
    import json, io
    mapping = {"sbox": SBOX, "inv_sbox": INV_SBOX, "name": f"S-box{sbox_choice}"}
    b = io.BytesIO(json.dumps(mapping).encode("utf-8"))
    st.download_button("Klik untuk download", data=b, file_name=f"sbox_{sbox_choice}.json", mime="application/json")

st.markdown("---")
st.caption("Catatan: S-box di-generate pake inverse GF(2^8) dan affine transform sesuai K-matrix di paper Alamsyah et al.")
