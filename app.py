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
st.title("Military-Grade Data Encryption")

menu = ["Store Data", "Retrieve Data", "Admin Login"] if not st.session_state.locked else ["Admin Login"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Store Data":
    st.subheader("Store Sensitive Data")
    
    user_data = st.text_area("Enter confidential data:", height=150)
    passkey = st.text_input("Create security passphrase:", type="password")
    confirm_passkey = st.text_input("Confirm passphrase:", type="password")
    
    if st.button("Encrypt & Store"):
        if not user_data:
            st.error("Please enter data to encrypt")
        elif passkey != confirm_passkey:
            st.error("Passphrases don't match!")
        else:
            data_id = auth.hash_passkey(passkey)[:16]
            encrypted = crypto.encrypt(user_data)
            data_manager.save_data(
                data_id=data_id,
                encrypted_text=encrypted,
                passkey_hash=auth.hash_passkey(passkey)
            )
            st.success(f"✅ Data secured! Your Data ID: {data_id}")

elif choice == "Retrieve Data":
    st.subheader("Access Secured Data")
    
    data_id = st.text_input("Enter Data ID:").strip()
    passkey = st.text_input("Enter security passphrase:", type="password")
    
    if st.button("Decrypt"):
        if not data_id or not passkey:
            st.error("Both fields are required!")
        else:
            record = data_manager.get_record(data_id)
            
            if record:
                st.write("### Debug Information")
                st.write("Stored Hash:", record["passkey_hash"])
                st.write("Computed Hash:", auth.hash_passkey(passkey))
                
                if auth.validate_passkey(passkey, record["passkey_hash"]):
                    decrypted = crypto.decrypt(record["encrypted"])
                    st.session_state.failed_attempts = 0
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted)
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Wrong passkey! {remaining} attempts left")
                    
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.locked = True
                        st.warning("System locked! Contact administrator")
                        st.rerun()
            else:
                st.error("❌ Data ID not found")

elif choice == "Admin Login":
    st.subheader("Administrator Access")
    admin_pass = st.text_input("Enter master password:", type="password")
    
    if st.button("Unlock System"):
        if admin_pass == "SecureDataEncryption":
            st.session_state.locked = False
            st.session_state.failed_attempts = 0
            st.success("✅ System unlocked! Redirecting...")
            st.rerun()
        else:
            st.error("❌ Invalid master password!")
