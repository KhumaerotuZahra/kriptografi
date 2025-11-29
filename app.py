import streamlit as st
import pandas as pd
import numpy as np

# ==========================================
# PART 1: CONSTANTS & MATH LOGIC
# ==========================================

# 1. Constants from Paper
AES_MODULUS = 0x11B  # Irreducible polynomial x^8 + x^4 + x^3 + x + 1
C_AES = 0x63         # Constant (Decimal 99)

# 2. Matrix Definitions
# These define the bit transformations for each S-box variant.
K_MATRICES = {
    "K-4": [
        0b00000111, 0b10000011, 0b11000001, 0b11100000,
        0b01110000, 0b00111000, 0b00011100, 0b00001110
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

@st.cache_data
def gf_multiply(a, b):
    """Galois Field multiplication modulo 0x11B"""
    p = 0
    for i in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set: a ^= AES_MODULUS
        b >>= 1
    return p % 256

@st.cache_data
def gf_inverse(val):
    """Finds multiplicative inverse in GF(2^8)"""
    if val == 0: return 0
    for i in range(1, 256):
        if gf_multiply(val, i) == 1:
            return i
    return 0

@st.cache_data
def affine_transform(byte_val, matrix):
    """
    Applies Affine Transformation matches the paper's specific vector math.
    Y = X * M + C
    """
    result = 0
    # Loop through bits of the input byte (MSB to LSB)
    for bit_pos in range(8):
        mask = 1 << (7 - bit_pos)
        if byte_val & mask:
            result ^= matrix[bit_pos]
            
    return result ^ C_AES

@st.cache_data
def generate_sbox_data(matrix_key):
    """Generates the S-box and Inverse S-box based on the matrix key."""
    # Handle the key name to get the raw list
    matrix = K_MATRICES[matrix_key]
    
    sbox = [0] * 256
    for i in range(256):
        inv = gf_inverse(i)
        sbox[i] = affine_transform(inv, matrix)
        
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
st.markdown("""
This application generates Cryptographic Substitution Boxes (S-Boxes) based on the paper:
*"AES S-box modification uses affine matrices exploration for increased S-box strength"* by Alamsyah et al.
""")

# --- Sidebar ---
st.sidebar.header("Configuration")
selected_matrix_name = st.sidebar.selectbox(
    "Select Affine Matrix (K-n)",
    options=list(K_MATRICES.keys()),
    index=1  # Default to K-44
)

# Generate S-box based on selection
sbox, inv_sbox = generate_sbox_data(selected_matrix_name)
short_name = selected_matrix_name.split()[0] # e.g., "K-44"

st.sidebar.success(f"Generated S-Box using {short_name}")

# --- Main Content ---
tab1, tab2, tab3 = st.tabs(["📊 S-Box Visualization", "🔒 Encrypt", "🔓 Decrypt"])

with tab1:
    st.header(f"S-Box Table: {short_name}")
    
    col_dec, col_hex = st.columns(2)
    
    with col_dec:
        st.subheader("Decimal Format")
        st.caption("Matches the paper's table style")
        # Create 16x16 DataFrame for Decimal
        df_dec = pd.DataFrame(
            np.array(sbox).reshape(16, 16),
            columns=[f"{i}" for i in range(16)],
            index=[f"{i}" for i in range(16)]
        )
        st.dataframe(df_dec, height=600)

    with col_hex:
        st.subheader("Hexadecimal Format")
        st.caption("Standard cryptographic notation")
        # Create 16x16 DataFrame for Hex
        hex_data = np.array([f"{x:02X}" for x in sbox]).reshape(16, 16)
        df_hex = pd.DataFrame(
            hex_data,
            columns=[f"{i:02X}" for i in range(16)],
            index=[f"{i:01X}0" for i in range(16)]
        )
        st.dataframe(df_hex, height=600)

with tab2:
    st.header("Encryption (Substitution)")
    text_input = st.text_input("Enter text to encrypt:", value="Alamsyah S-box")
    
    if text_input:
        # Encrypt
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
            
        st.markdown("---")
        st.markdown("*Detailed Breakdown:*")
        breakdown_data = {
            "Char": [char for char in text_input],
            "Original (Dec)": [b for b in input_bytes],
            "Substituted (Dec)": encrypted_ints,
            "Substituted (Hex)": [f"{x:02X}" for x in encrypted_ints]
        }
        st.dataframe(pd.DataFrame(breakdown_data))

with tab3:
    st.header("Decryption (Inverse Substitution)")
    st.markdown("Enter numbers separated by spaces or commas. You can mix Decimal (e.g. 99) and Hex (e.g. 63 or 0x63).")
    
    decrypt_input = st.text_area("Input Ciphertext:", height=100)
    
    if st.button("Decrypt"):
        if decrypt_input:
            try:
                # Cleaning and Parsing Logic
                raw_tokens = decrypt_input.replace(',', ' ').split()
                parsed_ints = []
                
                for token in raw_tokens:
                    token = token.strip()
                    if not token: continue
                    
                    # Auto-detect Hex
                    if token.lower().startswith("0x") or any(c in "abcdefABCDEF" for c in token):
                        parsed_ints.append(int(token, 16))
                    else:
                        parsed_ints.append(int(token))
                
                # Decrypt using Inverse S-box
                decrypted_bytes = bytes([inv_sbox[val] for val in parsed_ints])
                decrypted_text = decrypted_bytes.decode('utf-8', errors='replace')
                
                st.success("Decryption Successful!")
                st.subheader(f"Result: {decrypted_text}")
                
            except ValueError:
                st.error("Error parsing input. Please ensure all values are valid numbers or hex codes.")
            except Exception as e:
                st.error(f"An error occurred: {e}")
