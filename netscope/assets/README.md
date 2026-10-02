# App icon

Drop your icon here as **`icon.png`** (square, at least 1024×1024, transparent background),
then run, from the repo root:

```bash
pip install pillow
python packaging/make_icons.py
```

That generates `icon.icns` (macOS) and `icon.ico` (Windows) next to it. Every build and
shortcut picks them up automatically: the macOS `.app`, the Windows installer and desktop
shortcut, and `netscope --create-shortcut`. With no icon present, everything still builds
and uses the default system icon.
