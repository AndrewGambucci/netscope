#!/usr/bin/env python3
"""Generate icon.ico (Windows) and icon.icns (macOS) from netscope/assets/icon.png."""
import sys
from pathlib import Path

from PIL import Image

ASSETS = Path(__file__).resolve().parent.parent / "netscope" / "assets"
SOURCE = ASSETS / "icon.png"


def main() -> int:
    if not SOURCE.exists():
        print(f"Put your icon at {SOURCE} first (square PNG, 1024x1024+).", file=sys.stderr)
        return 1
    img = Image.open(SOURCE).convert("RGBA")
    if img.width != img.height:
        side = max(img.size)
        square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        square.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
        img = square
    if img.width < 512:
        print("Warning: icon is small; 1024x1024 looks best on Retina displays.", file=sys.stderr)

    img.save(ASSETS / "icon.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    big = img.resize((1024, 1024), Image.LANCZOS)
    big.save(ASSETS / "icon.icns")
    print("Wrote", ASSETS / "icon.ico", "and", ASSETS / "icon.icns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
