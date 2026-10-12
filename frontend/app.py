import os
import time
import streamlit as st
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="AI Assistant",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------- Sidebar Configuration -----------------
with st.sidebar:
    st.title("⚙️ Model Settings")

    model_option = st.selectbox(
        "Select Model",
        options=["gpt-4o", "gemini-1.5-pro", "claude-3-5-sonnet", "custom-backend"],
        index=0,
    )

    temperature = st.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=0.7,
        step=0.05,
        help="Higher values make output more random, lower values more deterministic.",
    )

    backend_url = st.text_input(
        "Backend API URL (optional)",
        value=os.getenv("BACKEND_API_URL", "http://localhost:8000/api/chat"),
        help="Endpoint for custom backend / model inference server",
    )

    system_prompt = st.text_area(
        "System Prompt",
        value="You are a helpful AI assistant specialized in cybersecurity and cloud intelligence.",
        height=100,
    )

    if st.button("🗑️ Clear Chat History", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

# ----------------- Chat State Initialization -----------------
if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": "Hello! I am your AI assistant. How can I help you today?",
        }
    ]

# ----------------- Helper: Model Response -----------------
def generate_ai_response(user_input: str) -> str:
    """
    Hook to call backend or LLM API.
    Attempts to call custom backend if available, otherwise falls back to simulated response.
    """
    if backend_url:
        try:
            payload = {
                "model": model_option,
                "temperature": temperature,
                "system_prompt": system_prompt,
                "messages": st.session_state.messages,
            }
            res = requests.post(backend_url, json=payload, timeout=5)
            if res.status_code == 200:
                data = res.json()
                return data.get("response") or data.get("content") or str(data)
        except Exception:
            # Backend not reachable or error; proceed with simulated demo response
            pass

    # Fallback simulated response for testing/demo
    return f"[Response from {model_option}]: Received your prompt: '{user_input}'. Ready to integrate with live backend endpoint."

# ----------------- Main Chat UI -----------------
st.title("🤖 AI Model Assistant")
st.caption(f"Currently active model: `{model_option}`")

# Display conversation history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# User prompt input
if prompt := st.chat_input("Type your message here..."):
    # Append & display user prompt
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Generate & stream/display assistant response
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        with st.spinner("Thinking..."):
            full_response = generate_ai_response(prompt)

            # Typing effect
            displayed_response = ""
            for word in full_response.split(" "):
                displayed_response += word + " "
                time.sleep(0.02)
                message_placeholder.markdown(displayed_response + "▌")
            message_placeholder.markdown(displayed_response.strip())

    # Save assistant response to history
    st.session_state.messages.append({"role": "assistant", "content": full_response})

