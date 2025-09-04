from pathlib import Path
import datetime as dt

HOME = Path.home()
NOW = dt.datetime.now().strftime("%Y%m%d-%H%M%S")

ARC_ROOT        = HOME / "Library/Application Support/Arc"
ARC_USER_DATA   = ARC_ROOT / "User Data"
ARC_LOCAL_STATE = ARC_USER_DATA / "Local State"
ARC_SIDEBAR     = ARC_ROOT / "StorableSidebar.json"

CHROME_ROOT        = HOME / "Library/Application Support/Google/Chrome"
CHROME_LOCAL_STATE = CHROME_ROOT / "Local State"

ZEN_CANDIDATES = [
    "/Applications/Zen Browser.app",
    "/Applications/Zen.app",
]

BASE_DIR    = Path(__file__).resolve().parent.parent
OUT_ROOT    = BASE_DIR / "arc-export"
PROFILES_DIR = OUT_ROOT / "profiles"

