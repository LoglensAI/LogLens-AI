#!/usr/bin/env python3

import sys

from sentence_transformers import SentenceTransformer

MODEL = "all-MiniLM-L6-v2"


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "_models"
    dest = f"{out}/{MODEL}"
    print(f"Downloading {MODEL} -> {dest}")
    SentenceTransformer(MODEL).save(dest)
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())