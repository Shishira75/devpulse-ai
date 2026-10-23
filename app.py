import streamlit as st
import re

# Page Configuration
st.set_page_config(
    page_title="DevPulse AI — Cloud Code Auditor",
    page_icon="⚡",
    layout="wide"
)

# Title & Description
st.title("⚡ DevPulse AI — Automated Cloud & Security Auditor")
st.markdown(
    "Scan your code, configuration templates, and serverless scripts for "
    "**security vulnerabilities**, **cloud misconfigurations**, and **performance bottlenecks**."
)

# Sidebar Configuration
st.sidebar.header("Audit Settings")
scan_mode = st.sidebar.selectbox("Scan Mode", ["Quick Security Scan", "Full Cloud Audit", "Cost Optimization"])
strictness = st.sidebar.slider("Audit Sensitivity", 1, 5, 4)

# File uploader and code text area
uploaded_file = st.file_uploader("Upload Python script, JSON, or YAML file", type=["py", "json", "yaml", "tf"])
code_input = st.text_area("...or paste code snippet directly:", height=220, placeholder="Paste your code here...")

sample_btn = st.button("Load Sample Cloud Code")
if sample_btn:
    code_input = (
        'import os\n'
        'import time\n\n'
        '# AWS Configuration\n'
        'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n'
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n\n'
        'def process_event(event):\n'
        '    # Overly permissive policy\n'
        '    permissions = {"Effect": "Allow", "Action": "*", "Resource": "*"}\n'
        '    # Synchronous blocking call\n'
        '    time.sleep(5)\n'
        '    return permissions\n'
    )
    st.rerun()

target_code = ""
if uploaded_file:
    target_code = uploaded_file.read().decode("utf-8")
elif code_input:
    target_code = code_input

# Run Audit Button
if st.button("⚡ Run DevPulse Audit", type="primary"):
    if not target_code.strip():
        st.warning("Please paste code or upload a file first.")
    else:
        st.write("---")
        st.subheader("Audit Report & Architectural Scorecard")

        issues = []
        health_score = 100

        # Rule 1: Hardcoded AWS Credentials
        if re.search(r'(?i)(aws_access_key_id|aws_secret_access_key|api_key|secret_key)\s*=\s*["\'][^"\']+["\']', target_code):
            issues.append({
                "severity": "CRITICAL",
                "title": "Hardcoded Cloud Credentials Detected",
                "desc": "Sensitive API/AWS access keys were found directly in source code.",
                "fix": "Use AWS Secrets Manager or environment variables (`os.getenv`) to securely load credentials."
            })
            health_score -= 40

        # Rule 2: Overly Permissive IAM Wildcard
        if "*" in target_code and any(keyword in target_code for keyword in ["Action", "Resource", "allow_origins"]):
            issues.append({
                "severity": "HIGH",
                "title": "Overly Permissive Wildcard Access (*)",
                "desc": "Wildcards detected in IAM policy statements or CORS definitions.",
                "fix": "Follow the principle of least privilege. Explicitly define required actions and resources."
            })
            health_score -= 25

        # Rule 3: Blocking Synchronous Calls
        if "time.sleep(" in target_code:
            issues.append({
                "severity": "MEDIUM",
                "title": "Synchronous Blocking Call (`time.sleep`)",
                "desc": "Thread-blocking sleeps lead to execution latency and increased serverless compute cost.",
                "fix": "Use non-blocking asynchronous event handlers (`asyncio.sleep`) or event-driven step functions."
            })
            health_score -= 15

        # Scorecard Metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Repository Health Score", f"{max(health_score, 10)} / 100")
        with col2:
            st.metric("Total Issues Flagged", len(issues))
        with col3:
            st.metric("Scan Status", "Completed")

        st.write("---")
        st.markdown("### Findings & Remediation Steps")

        if issues:
            for item in issues:
                if item["severity"] == "CRITICAL":
                    st.error(f"**[{item['severity']}] {item['title']}**\n\n{item['desc']}\n\n*Recommended Fix:* `{item['fix']}`")
                elif item["severity"] == "HIGH":
                    st.warning(f"**[{item['severity']}] {item['title']}**\n\n{item['desc']}\n\n*Recommended Fix:* `{item['fix']}`")
                else:
                    st.info(f"**[{item['severity']}] {item['title']}**\n\n{item['desc']}\n\n*Recommended Fix:* `{item['fix']}`")
        else:
            st.success("Great job! No major security misconfigurations or performance anti-patterns found.")
