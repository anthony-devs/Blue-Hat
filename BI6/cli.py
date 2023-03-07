import argparse
from .bi6 import bi6


def main():
    parser = argparse.ArgumentParser(
        description="A Hacking Tool for All"
    )
    args = parser.parse_args()
    bi6()
    print("Happy Hacking!")

if __name__ == "__main__":
    main()
