import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from web.app import app

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🛡️  SHIELDX Antivirus Web Server")
    print("="*60)
    print("  Starting server on http://0.0.0.0:5000")
    print("  Access it at: http://localhost:5000")
    print("  On college network: http://<your-ip>:5000")
    print("  Press CTRL+C to stop the server")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
