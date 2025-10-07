import os, sys
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(CURRENT_DIR)
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app import app as app  # expose your Flask app
os.makedirs(os.environ.get("UPLOAD_FOLDER", "/tmp/uploads"), exist_ok=True)
