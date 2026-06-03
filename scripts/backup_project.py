from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ITEMS = [
    "README.md",
    "README_DEPLOY.md",
    ".env.example",
    "Dockerfile",
    "docker-compose.yml",
    "deploy",
    "infra",
    "observability",
    "scripts",
    "store",
    "templates",
    "honeytrap",
    "requirements.txt",
    "manage.py",
    "db.sqlite3",
]
EXCLUDED_DIRS = {".git", ".venv", "venv", "logs", "backups", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
EXCLUDED_FILES = {"infra/secrets/django_secret"}


def iter_files(item: Path):
    if not item.exists():
        return
    if item.is_file():
        if item.as_posix().replace("\\", "/") not in EXCLUDED_FILES:
            yield item
        return
    for path in item.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.parts)
        if parts.intersection(EXCLUDED_DIRS):
            continue
        if path.as_posix().replace("\\", "/") in EXCLUDED_FILES:
            continue
        yield path


def build_archive(output_dir: Path, items: list[str]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    archive_path = output_dir / f"honey-{timestamp}.zip"

    with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in items:
            source = ROOT / item
            for file_path in iter_files(source):
                archive.write(file_path, file_path.relative_to(ROOT).as_posix())

    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a curated Honey Haven backup archive.")
    parser.add_argument("--output-dir", default="backups", help="Directory for backup archives.")
    parser.add_argument("--item", action="append", dest="items", help="Extra item to include. May be passed multiple times.")
    parser.add_argument("--dry-run", action="store_true", help="Show files that would be included without writing an archive.")
    args = parser.parse_args()

    items = list(DEFAULT_ITEMS)
    if args.items:
        items.extend(args.items)

    if args.dry_run:
        for item in items:
            source = ROOT / item
            for file_path in iter_files(source):
                print(file_path.relative_to(ROOT).as_posix())
        return 0

    archive_path = build_archive(ROOT / args.output_dir, items)
    print(f"Created backup archive: {archive_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
