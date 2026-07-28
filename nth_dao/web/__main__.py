import argparse
import os

from . import main


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the NTH DAO local hub")
    parser.add_argument(
        "--lan",
        action="store_true",
        help=(
            "listen on the local network and advertise a dialable federation "
            "URL; use only on a trusted LAN"
        ),
    )
    args = parser.parse_args()
    if args.lan:
        os.environ.setdefault("NTH_HOST", "0.0.0.0")
        os.environ.setdefault("NTH_ALLOW_REMOTE_BIND", "1")
        os.environ.setdefault("NTH_LAN_PUBLISH", "1")
        os.environ.setdefault("NTH_LAN_DISCOVERY", "1")
    main()
