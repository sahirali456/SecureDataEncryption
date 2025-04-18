import streamlit as st
from encryption_system.crypto import CryptoHandler
from data_manager.storage import DataManager
from auth_system.security import AuthSystem

crypto = CryptoHandler()
data_manager = DataManager()
auth = AuthSystem()

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked' not in st.session_state:
    st.session_state.locked = False

st.set_page_config(page_title="Secure Data Vault", layout="wide")
st.title("Military Grade Data Encryption")

menu = ["Store Data", "Retrieve Data", "Admin Login"] if not st.session_state.locked else ["Admin Login"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Store Data":
    st.subheader("Store Sensitive Data")
    
    user_data = st.text_area("Enter confidential data:", height=150)
    passkey = st.text_input("Create security passphrase:", type="password")
    confirm_passkey = st.text_input("Confirm passphrase:", type="password")
    
    if st.button("Encrypt & Store"):
        if passkey == confirm_passkey:
            data_id = auth.hash_passkey(passkey)[:16]
            encrypted = crypto.encrypt(user_data)
            data_manager.save_data(data_id, encrypted, auth.hash_passkey(passkey))
            st.success(f"Data secured! Your Data ID: {data_id}")
        else:
            st.error("Passphrases do not match!")

elif choice == "Retrieve Data":
    st.subheader("Access Secured Data")
    
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter security passphrase:", type="password")
    
    if st.button("Decrypt"):
        record = data_manager.get_record(data_id)
        if record and auth.validate_passkey(passkey, record["passkey_hash"]):
            decrypted = crypto.decrypt(record["encrypted"])
            st.session_state.failed_attempts = 0
            st.success("Decrypted Data:")
            st.code(decrypted)
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"Access denied! {remaining} attempts remaining")
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.locked = True
                st.warning("System locked! Contact administrator")
                st.experimental_rerun()

elif choice == "Admin Login":
    st.subheader("Administrator Access")
    admin_pass = st.text_input("Enter master password:", type="password")
    
    if st.button("Unlock System"):
        if admin_pass == "TopSecret123!":
            st.session_state.locked = False
            st.session_state.failed_attempts = 0
            st.success("System unlocked! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("Invalid master password!")