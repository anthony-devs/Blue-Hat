import argparse
from .bi6 import bi6


def main():
    parser = argparse.ArgumentParser(
        description="A Hacking Tool for All"
    )
    parser.add_argument(
        "start", type=str,
        help="The URL of the resource to be downloaded."
    )
    parser.add_argument(
        "--commands", "-c",
        help=("List Commands")
    )
    args = parser.parse_args()
    bi6()
    print("Happy Hacking!")

if __name__ == "__main__":
    main()