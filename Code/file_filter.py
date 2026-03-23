from pathlib import Path
import re
import shutil

import os
from dotenv import load_dotenv
load_dotenv('.env')

OUTPUT_FOLDER = Path(os.getenv("OUTPUT_FOLDER"))
PATCH_FILE_STORAGE_PATH = Path(os.getenv("PATCH_FILE_STORAGE_PATH"))
JS_TS_EXTENSIONS = {'.js', '.jsx', '.ts', '.tsx'}



def extract_modified_extensions(patch_path: Path) -> set:
    """
    Extract file extensions modified in a patch
    """
    extensions = set()

    try:
        with patch_path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if line.startswith("diff --git"):
                    parts = line.split()
                    if len(parts) >= 4:
                        for p in (parts[2], parts[3]):
                            p = re.sub(r"^(a/|b/)", "", p)
                            ext = Path(p).suffix.lower()
                            if ext:
                                extensions.add(ext)

                elif line.startswith("--- ") or line.startswith("+++ "):
                    path = line.split(maxsplit=1)[1]
                    if path != "/dev/null":
                        path = re.sub(r"^(a/|b/)", "", path)
                        ext = Path(path).suffix.lower()
                        if ext:
                            extensions.add(ext)

    except Exception:
        pass

    return extensions


def extract_js_ts_patches():
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)

    js_ts_patches = []
    total = 0

    for patch_file in PATCH_FILE_STORAGE_PATH.glob("*.patch"):
        total += 1
        exts = extract_modified_extensions(patch_file)

        if exts.intersection(JS_TS_EXTENSIONS):
            shutil.copy2(patch_file, OUTPUT_FOLDER / patch_file.name)
            js_ts_patches.append(patch_file.name)

    print(f"\nTotal patches scanned: {total}")
    print(f"JS / TS related patches: {len(js_ts_patches)}")

    if js_ts_patches:
        print("\nFiltered patch files:")
        for p in js_ts_patches:
            print(f"  - {p}")


if __name__ == "__main__":
    extract_js_ts_patches()

