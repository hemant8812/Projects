import streamlit as st
import hashlib
import requests
import re
from PyPDF2 import PdfReader

# --- Configuration & Styling ---
st.set_page_config(page_title="PDF Malware Analyzer", page_icon="🛡️")

def get_pdf_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def analyze_pdf_structure(file):
    """Scans for suspicious PDF keywords."""
    content = file.read().decode('latin-1', errors='ignore')
    file.seek(0) # Reset file pointer
    
    suspicious_keywords = {
        "/JavaScript": len(re.findall(r'/JavaScript', content)),
        "/JS": len(re.findall(r'/JS', content)),
        "/OpenAction": len(re.findall(r'/OpenAction', content)),
        "/AA": len(re.findall(r'/AA', content)),
        "/Launch": len(re.findall(r'/Launch', content)),
        "/EmbeddedFile": len(re.findall(r'/EmbeddedFile', content)),
    }
    return suspicious_keywords

def check_virustotal(file_hash, api_key):
    """Queries VirusTotal for file reputation."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

# --- UI Layout ---
st.title("🛡️ PDF Malware Analyzer")
st.markdown("Upload a PDF to scan for hidden scripts and malicious indicators.")

with st.sidebar:
    st.header("Settings")
    vt_api_key = st.text_input("VirusTotal API Key (Optional)", type="password")
    st.info("Static analysis works without an API key.")

uploaded_file = st.file_uploader("Drag and drop a PDF file", type="pdf")

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    sha256_hash = get_pdf_hash(file_bytes)
    
    st.subheader("File Information")
    st.text(f"Filename: {uploaded_file.name}")
    st.text(f"SHA-256: {sha256_hash}")

    # --- Static Analysis ---
    results = analyze_pdf_structure(uploaded_file)
    total_suspicious = sum(results.values())

    st.subheader("Static Analysis Results")
    cols = st.columns(3)
    for i, (key, count) in enumerate(results.items()):
        cols[i % 3].metric(label=key, value=count, delta="Suspicious" if count > 0 else None, delta_color="inverse")

    # --- Risk Scoring ---
    st.subheader("Risk Assessment")
    if total_suspicious == 0:
        st.success("Safe: No suspicious keywords found.")
    elif 1 <= total_suspicious <= 3:
        st.warning("Suspicious: Low-level automation detected. Review manually.")
    else:
        st.error("Malicious: High number of trigger actions/scripts detected!")

    # --- VirusTotal Integration ---
    if vt_api_key:
        st.divider()
        st.subheader("VirusTotal Reputation")
        vt_data = check_virustotal(sha256_hash, vt_api_key)
        
        if vt_data:
            stats = vt_data['data']['attributes']['last_analysis_stats']
            st.write(f"Malicious detections: {stats['malicious']} / {sum(stats.values())}")
            if stats['malicious'] > 0:
                st.error("Flagged by antivirus engines!")
            else:
                st.success("Clean according to VirusTotal.")
        else:
            st.info("File hash not found in VirusTotal database.")