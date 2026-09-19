import streamlit as st
import pandas as pd
import pickle
import re
import tldextract
from urllib.parse import urlparse


# =========================================
# PAGE CONFIGURATION
# =========================================

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)


# =========================================
# LOAD THE TRAINED MODEL
# =========================================

@st.cache_resource
def load_model():
    with open("phishing_model.pkl", "rb") as file:
        return pickle.load(file)


model = load_model()


# =========================================
# FEATURE EXTRACTION FUNCTION
# MUST MATCH THE NOTEBOOK EXACTLY
# =========================================

def extract_features(url):

    url = str(url).strip().lower()

    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    # Parse URL safely
    try:
        parsed = urlparse(url_to_parse)

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

    except Exception:
        hostname = ""
        path = ""
        query = ""

    # Extract domain information
    extracted = tldextract.extract(url_to_parse)

    subdomain = extracted.subdomain or ""
    domain = extracted.domain or ""

    # Suspicious words
    suspicious_words = [
        "login", "signin", "verify", "verification",
        "secure", "account", "update", "password",
        "confirm", "bank", "payment", "wallet",
        "authenticate", "security", "support"
    ]

    suspicious_count = sum(
        word in url
        for word in suspicious_words
    )

    # Check whether hostname is an IP address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    is_ip_address = int(
        bool(re.match(ip_pattern, hostname))
    )

    # Count subdomains
    subdomain_count = (
        subdomain.count(".") + 1
        if subdomain else 0
    )

    # Return EXACTLY the same 25 features
    return {

        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),

        "domain_length": len(domain),
        "subdomain_length": len(subdomain),
        "subdomain_count": subdomain_count,

        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "digit_count": sum(c.isdigit() for c in url),

        "slash_count": url.count("/"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "at_count": url.count("@"),

        "https": int(url.startswith("https://")),

        "suspicious_word_count": suspicious_count,

        "domain_has_digit": int(
            any(c.isdigit() for c in domain)
        ),

        "domain_has_hyphen": int(
            "-" in domain
        ),

        "query_length": len(query),

        "has_ip_address": is_ip_address,

        "double_slash_path": int(
            "//" in path
        ),

        "percent_count": url.count("%"),

        "colon_count": url.count(":"),

        "www_count": url.count("www"),

        "has_punycode": int(
            "xn--" in hostname
        )
    }


# =========================================
# OBSERVABLE URL ANALYSIS
# =========================================

def get_analysis_reasons(url):

    url = str(url).strip().lower()

    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)

        hostname = parsed.hostname or ""
        path = parsed.path or ""

    except Exception:
        hostname = ""
        path = ""

    extracted = tldextract.extract(url_to_parse)

    subdomain = extracted.subdomain or ""
    domain = extracted.domain or ""

    reasons = []

    suspicious_words = [
        "login", "signin", "verify", "verification",
        "secure", "account", "update", "password",
        "confirm", "bank", "payment", "wallet",
        "authenticate", "security", "support"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url
    ]

    # Suspicious words
    if found_words:
        reasons.append(
            "The URL contains potentially suspicious terms: "
            + ", ".join(found_words)
        )

    # Hyphens
    hyphen_count = url.count("-")

    if hyphen_count >= 2:
        reasons.append(
            f"The URL contains {hyphen_count} hyphens, "
            "which creates a more complex URL structure."
        )

    # Subdomain
    if subdomain:
        reasons.append(
            f"The URL uses a subdomain structure: '{subdomain}'."
        )

    # Digits in domain
    if any(c.isdigit() for c in domain):
        reasons.append(
            "The main domain contains numeric characters."
        )

    # Hyphen in main domain
    if "-" in domain:
        reasons.append(
            "The main domain contains a hyphen."
        )

    # @ symbol
    if "@" in url:
        reasons.append(
            "The URL contains an '@' symbol, which can make "
            "a URL misleading."
        )

    # Punycode
    if "xn--" in hostname:
        reasons.append(
            "The URL contains Punycode, which can sometimes "
            "be associated with lookalike-domain attacks."
        )

    # IP address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        reasons.append(
            "The URL uses an IP address instead of a normal domain name."
        )

    # Long URL
    if len(url) > 75:
        reasons.append(
            "The URL is unusually long and may obscure its destination."
        )

    # HTTPS
    if not url.startswith("https://"):
        reasons.append(
            "The URL does not use HTTPS."
        )

    # Double slash inside path
    if "//" in path:
        reasons.append(
            "The URL contains an unusual double-slash structure in its path."
        )

    # If no obvious characteristic is found
    if not reasons:
        reasons.append(
            "No single strong suspicious characteristic was found. "
            "The prediction is based on the combined URL feature pattern "
            "analyzed by the machine learning model."
        )

    return reasons


# =========================================
# PREDICTION FUNCTION
# =========================================

def predict_url(url):

    # Extract the 25 features
    features = extract_features(url)

    # Convert to DataFrame
    input_data = pd.DataFrame([features])

    # Get probabilities
    probabilities = model.predict_proba(input_data)[0]

    # Model classes:
    # 0 = bad/phishing
    # 1 = good/legitimate

    bad_probability = probabilities[0]
    good_probability = probabilities[1]

    # =====================================
    # SECURITY-FOCUSED THRESHOLD
    # =====================================

    FINAL_THRESHOLD = 0.65

    # URL is considered legitimate only if
    # good probability is at least 65%
    if good_probability >= FINAL_THRESHOLD:
        prediction = "good"
    else:
        prediction = "bad"

    confidence = max(
        bad_probability,
        good_probability
    ) * 100

    return (
        prediction,
        confidence,
        bad_probability * 100,
        good_probability * 100
    )


# =========================================
# STREAMLIT USER INTERFACE
# =========================================

st.title("🛡️ Phishing URL Detector")

st.write(
    "Enter a website URL below to analyze whether it is "
    "potentially legitimate or phishing."
)

st.info(
    "This system uses Machine Learning and URL feature analysis "
    "with a security-focused decision threshold."
)


# =========================================
# URL INPUT
# =========================================

url = st.text_input(
    "Enter Website URL",
    placeholder="https://www.example.com"
)


# =========================================
# ANALYZE BUTTON
# =========================================

if st.button("🔍 Analyze URL"):

    if url.strip() == "":

        st.warning("⚠️ Please enter a website URL.")

    else:

        with st.spinner("Analyzing URL..."):

            (
                prediction,
                confidence,
                bad_probability,
                good_probability
            ) = predict_url(url)

            reasons = get_analysis_reasons(url)

        st.divider()

        # =====================================
        # ANALYSIS RESULT
        # =====================================

        st.subheader("📊 Analysis Result")

        st.write("**URL:**", url)

        if prediction == "good":

            st.success(
                "✅ Prediction: LEGITIMATE / GOOD"
            )

        else:

            st.error(
                "⚠️ Prediction: POTENTIALLY PHISHING / BAD"
            )

        st.write(
            f"**Model Confidence:** {confidence:.2f}%"
        )

        st.write(
            f"🔴 Phishing / Bad Probability: "
            f"**{bad_probability:.2f}%**"
        )

        st.write(
            f"🟢 Legitimate / Good Probability: "
            f"**{good_probability:.2f}%**"
        )

        st.divider()

        # =====================================
        # WHY THIS RESULT?
        # =====================================

        st.subheader("🔍 Why was this result given?")

        if prediction == "bad":

            st.write(
                f"The model assigned **{good_probability:.2f}%** "
                f"probability to the legitimate class. "
                f"This is below the required **65% threshold** "
                f"for classification as legitimate."
            )

        else:

            st.write(
                f"The model assigned **{good_probability:.2f}%** "
                f"probability to the legitimate class, which meets "
                f"the required **65% threshold**."
            )

        st.write("### Observed URL Characteristics")

        for reason in reasons:
            st.write(f"• {reason}")

        st.divider()

        # =====================================
        # SECURITY RECOMMENDATION
        # =====================================

        if prediction == "bad":

            st.warning(
                "⚠️ Security Recommendation: Exercise caution before "
                "opening this URL or entering passwords, banking details, "
                "or other sensitive information."
            )

        else:

            st.success(
                "✅ The URL meets the model's legitimate-confidence "
                "threshold. However, normal online security precautions "
                "are still recommended."
            )

        st.caption(
            "Note: The explanation shows observable URL characteristics "
            "and the machine learning decision process. It does not prove "
            "that a specific URL is malicious. No phishing detection "
            "system can guarantee detection of every malicious URL."
        )