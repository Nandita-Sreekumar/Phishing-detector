import httpx
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Configure page
st.set_page_config(
    page_title="PhishDetect AI",
    page_icon="🛡️",
    layout="wide"
)

# API base URL
API_URL = "http://localhost:8000/api/v1"


def main():
    """Main dashboard application."""

    st.title("🛡️ PhishDetect AI")
    st.markdown("*AI-Powered Phishing & Deepfake Detection*")

    # Create tabs
    tab1, tab2, tab3 = st.tabs(["📧 Email Analysis", "🔗 URL Scanner", "🖼️ Image Detector"])

    with tab1:
        email_analysis_tab()

    with tab2:
        url_analysis_tab()

    with tab3:
        image_analysis_tab()


def email_analysis_tab():
    """Email analysis tab."""
    st.header("Email Analysis")

    email_text = st.text_area(
        "Paste email content (including headers if available):",
        height=300,
        placeholder="From: sender@example.com\\nSubject: Urgent!\\n\\nEmail body..."
    )

    if st.button("🔍 Analyze Email", type="primary"):
        if email_text:
            with st.spinner("Analyzing email..."):
                try:
                    response = httpx.post(
                        f"{API_URL}/analyze/email",
                        json={"raw_email": email_text},
                        timeout=500.0
                    )

                    if response.status_code == 200:
                        result = response.json()
                        display_threat_assessment(result)
                    else:
                        st.error(f"Error: {response.status_code}")

                except Exception as e:
                    st.error(f"Error analyzing email: {e}")
        else:
            st.warning("Please enter email content")


def url_analysis_tab():
    """URL analysis tab."""
    st.header("URL Scanner")

    url = st.text_input(
        "Enter URL to analyze:",
        placeholder="<https://example.com/suspicious-link>"
    )

    if st.button("🔍 Analyze URL", type="primary"):
        if url:
            with st.spinner("Analyzing URL..."):
                try:
                    response = httpx.post(
                        f"{API_URL}/analyze/url",
                        json={"url": url},
                        timeout=30.0
                    )

                    if response.status_code == 200:
                        result = response.json()
                        display_threat_assessment(result)
                    else:
                        st.error(f"Error: {response.status_code}")

                except Exception as e:
                    st.error(f"Error analyzing URL: {e}")
        else:
            st.warning("Please enter a URL")


def image_analysis_tab():
    """Image analysis tab."""
    st.header("Image Detector")

    uploaded_file = st.file_uploader(
        "Upload image to analyze:",
        type=['png', 'jpg', 'jpeg', 'webp']
    )

    if uploaded_file is not None:
        # Display image
        st.image(uploaded_file, caption="Uploaded Image", width='stretch')

        if st.button("🔍 Analyze Image", type="primary"):
            with st.spinner("Analyzing image..."):
                try:
                    # Reset file pointer
                    uploaded_file.seek(0)

                    files = {"file": uploaded_file}
                    response = httpx.post(
                        f"{API_URL}/analyze/image",
                        files=files,
                        timeout=30.0
                    )

                    if response.status_code == 200:
                        result = response.json()
                        display_image_analysis(result)
                    else:
                        st.error(f"Error: {response.status_code}")

                except Exception as e:
                    st.error(f"Error analyzing image: {e}")


def display_threat_assessment(result: dict):
    """Display threat assessment results."""

    # Threat score card
    risk_level = result["risk_level"]
    score = result["overall_score"]

    # Color coding
    if risk_level == "phishing":
        color = "🔴"
        bg_color = "#ffebee"
    elif risk_level == "likely_phishing":
        color = "🟠"
        bg_color = "#fff3e0"
    elif risk_level == "suspicious":
        color = "🟡"
        bg_color = "#fffde7"
    else:
        color = "🟢"
        bg_color = "#e8f5e9"

    st.markdown(f"""
    <div style='background-color: {bg_color}; padding: 20px; border-radius: 10px; margin: 20px 0;'>
        <h2 style='margin: 0;'>{color} Threat Score: {score}/100</h2>
        <h3 style='margin: 10px 0 0 0;'>Risk Level: {risk_level.upper().replace('_', ' ')}</h3>
    </div>
    """, unsafe_allow_html=True)

    # Signal breakdown
    st.subheader("📊 Signal Breakdown")

    signals = result.get("signals", [])
    if signals:
        # Create bar chart
        signal_names = [s["name"] for s in signals]
        signal_scores = [s["score"] for s in signals]

        fig = go.Figure(data=[
            go.Bar(
                x=signal_scores,
                y=signal_names,
                orientation='h',
                marker=dict(
                    color=signal_scores,
                    colorscale='RdYlGn_r',
                    line=dict(color='rgb(8,48,107)', width=1.5)
                )
            )
        ])

        fig.update_layout(
            title="Threat Signals",
            xaxis_title="Score",
            yaxis_title="Signal",
            height=300
        )

        st.plotly_chart(fig, width='stretch')

    # Recommendations
    recommendations = result.get("recommendations", [])
    if recommendations:
        st.subheader("💡 Recommendations")
        for rec in recommendations:
            st.markdown(f"• {rec}")

    # IOCs
    iocs = result.get("iocs", [])
    if iocs:
        st.subheader("🎯 Indicators of Compromise (IOCs)")
        for ioc in iocs:
            st.code(ioc)


def display_image_analysis(result: dict):
    """Display image analysis results."""

    ai_prob = result.get("ai_generated_probability", 0)

    # Probability gauge
    st.subheader("🤖 AI Generation Probability")

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=ai_prob * 100,
        title={'text': "AI Generation Likelihood (%)"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 30], 'color': "lightgreen"},
                {'range': [30, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))

    fig.update_layout(height=300)
    st.plotly_chart(fig, width='stretch')

    # Metadata info
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📋 Metadata Analysis")
        st.write(f"**Has EXIF Data:** {'✅' if result.get('has_exif') else '❌'}")
        st.write(f"**Camera Make:** {result.get('camera_make', 'N/A')}")
        st.write(f"**Camera Model:** {result.get('camera_model', 'N/A')}")
        st.write(f"**Software:** {result.get('software', 'N/A')}")

    with col2:
        st.subheader("📊 Statistical Analysis")
        st.write(f"**Noise Uniformity:** {result.get('noise_uniformity', 0):.2f}")
        st.write(f"**AI Tool Signature:** {'✅' if result.get('ai_tool_signature') else '❌'}")

    # Limitations note
    st.info(result.get("limitations_note", ""))


if __name__ == "__main__":
    main()