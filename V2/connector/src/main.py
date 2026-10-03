import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lookout_connector.connector import LookoutConnector  # noqa: E402

if __name__ == "__main__":
    try:
        LookoutConnector().start()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
