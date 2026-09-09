"""
One-Click Standalone Runner for AWSSecurity AI.
Runs the complete cyber defense platform locally with ZERO AWS dependencies.
"""
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

import uvicorn

if __name__ == "__main__":
    os.environ["DEPLOYMENT_MODE"] = "STANDALONE_LOCAL"
    
    print("=" * 68)
    print("  [AWSSECURITY AI] STANDALONE CYBER DEFENSE PLATFORM")
    print("=" * 68)
    print("  [+] Mode:             STANDALONE (Zero AWS Cloud Dependencies)")
    print("  [+] Database:         Local Document Store / Standalone MongoDB")
    print("  [+] SIEM & Monitor:   Built-in Local Telemetry (Zero CloudWatch required)")
    print("  [+] ML Risk Engine:   Local Scikit-Learn & TensorFlow Neural Autoencoder")
    print("  [+] Alert Dispatch:   In-App Security Alert Inbox (Zero SNS required)")
    print("  [+] Access Portal:    http://127.0.0.1:8000")
    print("=" * 68)
    print("Starting local server... Press Ctrl+C to stop.\n")

    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
