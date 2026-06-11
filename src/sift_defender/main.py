"""AEGIS-IR entry point."""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def main():
    """Start the web dashboard."""
    import uvicorn
    from sift_defender.web.app import create_app

    app = create_app()

    print("\n" + "=" * 60)
    print("  AEGIS-IR")
    print("  Autonomous Evidence-Guided Investigation System")
    print("=" * 60)
    print(f"\n  Dashboard: http://localhost:8080")
    print(f"  Evidence:  {os.environ.get('SIFT_EVIDENCE_MOUNT', '/mnt/evidence')}")
    print("=" * 60 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")


if __name__ == "__main__":
    main()
