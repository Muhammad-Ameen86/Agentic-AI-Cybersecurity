import os
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Sentinel AI is running 🚀"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port)