import streamlit as st
import numpy as np

# --------------------------
# GF(2^8) helpers (AES poly)
# --------------------------
AES_MODULUS = 0x11B
C_AES = 0x63

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
# K-Matrices (only S-box44 fixed for now)
# --------------------------
K_MATRICES = {
    "44": [
        0b01110000,
        0b01110101,
        0b00111000,
        0b10111010,
        0b00011100,
        0b01011101,
        0b00001111,
        0b10101110
    ]
}

def affine_transform(matrix_rows, byte_val, c=C_AES):
    res = 0
    for i in range(8):
        row = matrix_rows[i]
        parity = bin(row & byte_val).count('1') % 2
        res |= (parity << i)
    return res ^ c

def generate_sbox_from_K(k_name):
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
# Crypto ops
# --------------------------
def encrypt_bytes(b, sbox):
    return bytes([sbox[x] for x in b])

def decrypt_bytes(b, inv_sbox):
    return bytes([inv_sbox[x] for x in b])


# --------------------------
# Streamlit UI
# --------------------------
st.set_page_config(
    page_title="S-Box 44 Crypto Demo",
    layout="wide",
)

# styling
st.markdown("""
<style>
    .title {
        font-size: 32px;
        font-weight: 700;
        color: #4A90E2;
    }
    .subtitle {
        font-size: 18px;
        color: #555;
    }
    .cipherbox {
        padding: 10px;
        background: #f7faff;
        border-radius: 8px;
        border: 1px solid #d0dff7;
        font-weight: 600;
        letter-spacing: 1px;
    }
    .sbox-table td {
        text-align: center !important;
        padding: 6px 10px !important;
        border: 1px solid #ddd;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='title'>S-Box 44 Substitution Cipher Demo</div>", unsafe_allow_html=True)
st.markdown("<div class='subtitle'>Kriptografi – Generate, Encrypt, Decrypt</div><br>", unsafe_allow_html=True)

sbox = generate_sbox_from_K("44")
inv_sbox = inverse_sbox(sbox)

# ===========================================================
# INPUT
# ===========================================================
st.markdown("### 🔤 Input Teks")
text = st.text_area("Masukkan teks yang ingin dienkripsi:", "Hello, Alamsyah!", height=120)

colE, colD = st.columns(2)

# ===========================================================
# ENCRYPT
# ===========================================================
if colE.button("🔐 Encrypt"):
    enc = encrypt_bytes(text.encode("utf-8"), sbox)
    st.session_state["enc"] = enc

# ===========================================================
# DECRYPT
# ===========================================================
if colD.button("🔓 Decrypt"):
    if "enc" in st.session_state:
        dec = decrypt_bytes(st.session_state["enc"], inv_sbox)
        st.session_state["dec"] = dec.decode("utf-8", errors="replace")
    else:
        st.warning("Belum ada ciphertext!")

# ===========================================================
# OUTPUT
# ===========================================================
if "enc" in st.session_state:
    st.markdown("### 🔒 Ciphertext (Hex)")
    hex_out = " ".join(f"{b:02X}" for b in st.session_state["enc"])
    st.markdown(f"<div class='cipherbox'>{hex_out}</div>", unsafe_allow_html=True)

if "dec" in st.session_state:
    st.markdown("### 🔁 Hasil Decrypt")
    st.success(st.session_state["dec"])

# ===========================================================
# S-BOX TABLE (16×16)
# ===========================================================
st.markdown("### 🔢 S-Box 44 Mapping (16×16)")

table_html = "<table class='sbox-table'>"
for r in range(16):
    table_html += "<tr>"
    for c in range(16):
        val = sbox[r*16 + c]
        table_html += f"<td>{val:02X}</td>"
    table_html += "</tr>"
table_html += "</table>"

st.markdown(table_html, unsafe_allow_html=True)
