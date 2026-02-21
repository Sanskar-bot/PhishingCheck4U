"""
start.py - Launch PhishingCheck4U.
Place in project root (same folder as the app/ directory).

Run with:
    .\\venv\\Scripts\\python.exe start.py
"""

import sys
import os

# Add project root to path so 'app' module is always found
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
