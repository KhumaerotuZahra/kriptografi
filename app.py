import streamlit as st

# ============================
# GF(2^8) helpers
# ============================
AES_MODULUS = 0x11B
C_AES = 0x63

def gf_multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0x1FF  # keep intermediate small
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

# ============================
# K-Matrices (fixed)
# ============================
K_MATRICES = {
    "4": [
        0b00000111, 0b10000011, 0b11000001, 0b11100000,
        0b01110000, 0b00111000, 0b00011100, 0b00001111
    ],

    "44": [
        0b01110000, 0b01110101, 0b00111000, 0b10111010,
        0b00011100, 0b01011101, 0b00001111, 0b10101110
    ],

    "81": [
        0b10100001, 0b11010000, 0b01101000, 0b00110100,
        0b00011010, 0b00001101, 0b10000110, 0b01000011
    ],

    "111": [
        0b11011100, 0b01101110, 0b00110111, 0b10011011,
        0b11001101, 0b11100110, 0b01110011, 0b10111001
    ],

    "128": [
        0b11111110, 0b01111111, 0b10111111, 0b11011111,
        0b11101111, 0b11110111, 0b11111011, 0b11111101
    ]
}

# ============================
# S-box generator & utils
# ============================
def affine_transform(matrix_rows, byte_val, c=C_AES):
    res = 0
    for i in range(8):
        row = matrix_rows[i]
        parity = bin(row & byte_val).count('1') % 2
        res |= (parity << i)
    return res ^ c

def generate_sbox(k_id):
    K = K_MATRICES[k_id]
    sbox = [0] * 256
    for x in range(256):
        inv = gf_inverse(x)
        sbox[x] = affine_transform(K, inv)
    return sbox

def inverse_sbox(sbox):
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

# ============================
# Crypto ops
# ============================
def encrypt_bytes(b, sbox):
    return bytes([sbox[x] for x in b])

def decrypt_bytes(b, inv_sbox):
    return bytes([inv_sbox[x] for x in b])

# ============================
# Streamlit UI
# ============================
st.set_page_config(page_title="S-Box Substitution Demo", layout="wide")

# simple styling
st.markdown("""
<style>
.title { font-size:28px; font-weight:700; color:#2B6CB0; }
.subtitle { color:#555; margin-bottom:8px; }
.cipherbox { padding:10px; background:#f3f7ff; border-radius:8px; border:1px solid #cfe0ff; font-family:monospace; }
.sbox-table td { text-align:center !important; padding:6px 8px !important; border:1px solid #eee; font-family:monospace; }
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='title'>S-Box Substitution Cipher</div>", unsafe_allow_html=True)
st.markdown("<div class='subtitle'>Pilih S-Box, enkripsi teks, lihat mapping 16×16</div>", unsafe_allow_html=True)

# pick S-box
sbox_id = st.selectbox("Pilih S-box", ["4", "44", "81", "111", "128"], index=1)
sbox = generate_sbox(sbox_id)
inv_sbox = inverse_sbox(sbox)

st.markdown(f"*S-box terpilih:* {sbox_id}")

# input area
st.markdown("### Input Teks")
text = st.text_area("Masukkan teks yang mau dienkripsi:", "Hello, Alamsyah!", height=120)

colE, colD = st.columns([1,1])

with colE:
    if st.button("🔐 Encrypt"):
        try:
            enc = encrypt_bytes(text.encode("utf-8"), sbox)
            st.session_state["enc"] = enc
        except Exception as e:
            st.error(f"Encrypt error: {e}")

with colD:
    if st.button("🔓 Decrypt"):
        if "enc" not in st.session_state:
            st.warning("Belum ada ciphertext (klik Encrypt dulu).")
        else:
            try:
                dec = decrypt_bytes(st.session_state["enc"], inv_sbox)
                # try decode utf-8, fallback to latin-1 to avoid crash
                try:
                    st.session_state["dec_text"] = dec.decode("utf-8")
                except:
                    st.session_state["dec_text"] = dec.decode("latin-1", errors="replace")
            except Exception as e:
                st.error(f"Decrypt error: {e}")

# output
if "enc" in st.session_state:
    st.markdown("### Ciphertext (Hex)")
    hex_out = " ".join(f"{b:02X}" for b in st.session_state["enc"])
    st.markdown(f"<div class='cipherbox'>{hex_out}</div>", unsafe_allow_html=True)

if "dec_text" in st.session_state:
    st.markdown("### Hasil Decrypt")
    st.success(st.session_state["dec_text"])

# verification small check
st.markdown("### Verifikasi singkat (beberapa indeks)")
v0 = sbox[0]
v15 = sbox[15]
v255 = sbox[255]
st.write(f"Index 0 → {v0:02X}    |    Index 15 → {v15:02X}    |    Index 255 → {v255:02X}")

# S-box table 16x16
st.markdown("### S-Box Mapping (16×16)")
table_html = "<table class='sbox-table'>"
for r in range(16):
    table_html += "<tr>"
    for c in range(16):
        table_html += f"<td>{sbox[r*16 + c]:02X}</td>"
    table_html += "</tr>"
table_html += "</table>"

st.markdown(table_html, unsafe_allow_html=True)
