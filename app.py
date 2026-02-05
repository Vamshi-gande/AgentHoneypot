# app.py
# Hugging Face Spaces entrypoint

from honeypot_api import app

# HF Spaces runs on port 7860
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port)
