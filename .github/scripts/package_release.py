#!/usr/bin/env python3
"""Create a single-file release archive with normalized metadata."""

import argparse
import datetime
import gzip
import io
import stat
import tarfile
import zipfile
from pathlib import Path


def zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    if not 1980 <= value.year <= 2107:
        raise ValueError("ZIP source date must be between 1980 and 2107")
    return (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second - value.second % 2,
    )


def write_zip(binary: Path, archive: Path, data: bytes, epoch: int) -> None:
    entry = zipfile.ZipInfo(binary.name, zip_timestamp(epoch))
    entry.create_system = 3
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = (stat.S_IFREG | 0o755) << 16
    entry.extra = b""
    entry.comment = b""
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as output:
        output.writestr(
            entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
        )


def write_tar_gz(binary: Path, archive: Path, data: bytes, epoch: int) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
            ) as output:
                entry = tarfile.TarInfo(binary.name)
                entry.size = len(data)
                entry.mtime = epoch
                entry.mode = 0o755
                entry.uid = 0
                entry.gid = 0
                entry.uname = ""
                entry.gname = ""
                output.addfile(entry, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args()

    if args.source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    data = args.binary.read_bytes()
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    if args.archive.name.endswith(".tar.gz"):
        write_tar_gz(args.binary, args.archive, data, args.source_date_epoch)
    elif args.archive.suffix == ".zip":
        write_zip(args.binary, args.archive, data, args.source_date_epoch)
    else:
        raise ValueError(f"unsupported archive format: {args.archive}")


if __name__ == "__main__":
    main()
