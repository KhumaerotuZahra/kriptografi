import streamlit as st
import pandas as pd
import numpy as np

# ==========================================
# PART 1: CONSTANTS & MATH LOGIC
# ==========================================

AES_MODULUS = 0x11B  # Irreducible polynomial
C_AES = 0x63         # Constant (Decimal 99)

# Matrix Definitions
# NOTE: K-4 has been corrected to end in 0x0E (not 0x0F).
K_MATRICES = {
    "K-4": [
        0b00000111, 0b10000011, 0b11000001, 0b11100000,
        0b01110000, 0b00111000, 0b00011100, 0b00001110  # Corrected LSB
    ],
    "K-44 (Proposed Best)": [
        0b01010111, 0b10101011, 0b11010101, 0b11101010,
        0b01110101, 0b10111010, 0b01011101, 0b10101110
    ],
    "K-81": [
        0b10100001, 0b11010000, 0b01101000, 0b00110100,
        0b00011010, 0b00001101, 0b10000110, 0b01000011
    ],
    "K-111": [
        0b11011100, 0b01101110, 0b00110111, 0b10011011,
        0b11001101, 0b11100110, 0b01110011, 0b10111001
    ],
    "K-128": [
        0b11111110, 0b01111111, 0b10111111, 0b11011111,
        0b11101111, 0b11110111, 0b11111011, 0b11111101
    ]
}

# Remove cache from simple math to ensure no stale data issues
def gf_multiply(a, b):
    p = 0
    for i in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set: a ^= AES_MODULUS
        b >>= 1
    return p % 256

def gf_inverse(val):
    if val == 0: return 0
    for i in range(1, 256):
        if gf_multiply(val, i) == 1:
            return i
    return 0

def affine_transform(byte_val, matrix):
    result = 0
    for bit_pos in range(8):
        mask = 1 << (7 - bit_pos)
        if byte_val & mask:
            result ^= matrix[bit_pos]
    return result ^ C_AES

# Cache based on the MATRIX CONTENT, not just the name.
# This ensures if the code changes, the cache invalidates.
@st.cache_data
def generate_sbox_data(matrix_data):
    sbox = [0] * 256
    for i in range(256):
        inv = gf_inverse(i)
        sbox[i] = affine_transform(inv, matrix_data)
        
    inv_sbox = [0] * 256
    for i in range(256):
        val = sbox[i]
        inv_sbox[val] = i
        
    return sbox, inv_sbox

# ==========================================
# PART 2: STREAMLIT UI
# ==========================================

st.set_page_config(page_title="AES S-Box Explorer", layout="wide")

st.title("🔐 AES S-Box Modification Explorer")

# --- Sidebar ---
st.sidebar.header("Configuration")
selected_matrix_name = st.sidebar.selectbox(
    "Select Affine Matrix (K-n)",
    options=list(K_MATRICES.keys()),
    index=0 
)

# Pass the actual LIST of integers to the function.
# This forces Streamlit to re-run if the numbers in the list change.
matrix_values = K_MATRICES[selected_matrix_name]
sbox, inv_sbox = generate_sbox_data(matrix_values)
short_name = selected_matrix_name.split()[0]

st.sidebar.success(f"Generated S-Box using {short_name}")

if st.sidebar.button("Clear Cache"):
    st.cache_data.clear()

# --- Main Content ---
tab1, tab2, tab3 = st.tabs(["📊 S-Box Visualization", "🔒 Encrypt", "🔓 Decrypt"])

with tab1:
    st.header(f"S-Box Table: {short_name}")
    col_dec, col_hex = st.columns(2)
    
    with col_dec:
        st.subheader("Decimal Format")
        # Create 16x16 DataFrame for Decimal
        df_dec = pd.DataFrame(
            np.array(sbox).reshape(16, 16),
            columns=[f"{i}" for i in range(16)],
            index=[f"{i}" for i in range(16)]
        )
        st.dataframe(df_dec, height=600)

    with col_hex:
        st.subheader("Hexadecimal Format")
        # Create 16x16 DataFrame for Hex
        hex_data = np.array([f"{x:02X}" for x in sbox]).reshape(16, 16)
        df_hex = pd.DataFrame(
            hex_data,
            columns=[f"{i:02X}" for i in range(16)],
            index=[f"{i:01X}0" for i in range(16)]
        )
        st.dataframe(df_hex, height=600)

with tab2:
    st.header("Encryption")
    text_input = st.text_input("Enter text to encrypt:", value="Alamsyah S-box")
    
    if text_input:
        input_bytes = text_input.encode('utf-8')
        encrypted_ints = [sbox[b] for b in input_bytes]
        
        st.subheader("Results")
        c1, c2 = st.columns(2)
        with c1:
            st.info("*Decimal Output:*")
            st.code(" ".join(map(str, encrypted_ints)))
        with c2:
            st.warning("*Hex Output:*")
            hex_output = " ".join([f"{x:02X}" for x in encrypted_ints])
            st.code(hex_output)

with tab3:
    st.header("Decryption")
    decrypt_input = st.text_area("Input Ciphertext (Decimal or Hex):", height=100)
    
    if st.button("Decrypt"):
        if decrypt_input:
            try:
                raw_tokens = decrypt_input.replace(',', ' ').split()
                parsed_ints = []
                for token in raw_tokens:
                    token = token.strip()
                    if not token: continue
                    if token.lower().startswith("0x") or any(c in "abcdefABCDEF" for c in token):
                        parsed_ints.append(int(token, 16))
                    else:
                        parsed_ints.append(int(token))
                
                decrypted_bytes = bytes([inv_sbox[val] for val in parsed_ints])
                decrypted_text = decrypted_bytes.decode('utf-8', errors='replace')
                st.success("Decryption Successful!")
                st.subheader(f"Result: {decrypted_text}")
            except Exception as e:
                st.error(f"Error: {e}")
