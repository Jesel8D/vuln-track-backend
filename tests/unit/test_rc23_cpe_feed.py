"""Offline tests of the official tar layout and the fixed-origin download contract."""

import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from app.services import cpe_feed

SAMPLE = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/nvd_cpe_rc23_verified.json").read_text()
)["products"]


def archive(tmp_path, *, path_override=None, link=False):
    path = tmp_path / "official.tar.gz"
    pieces = []
    with tarfile.open(path, "w:gz") as tar:
        for number, records in enumerate([SAMPLE[:2], SAMPLE[2:]], 1):
            body = json.dumps(
                {
                    "format": "NVD_CPE",
                    "version": "2.0",
                    "resultsPerPage": len(records),
                    "startIndex": number,
                    "totalResults": len(SAMPLE),
                    "products": records,
                },
                ensure_ascii=False,
            ).encode()
            pieces.append(body)
            member = tarfile.TarInfo(
                path_override or f"nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-{number:05}.json"
            )
            member.size = len(body)
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "/tmp/foreign"
            tar.addfile(member, io.BytesIO(body))
    data = b"".join(pieces)
    meta = cpe_feed.FeedMeta(
        hashlib.sha256(data).hexdigest(),
        datetime.now(UTC),
        len(data),
        path.stat().st_size,
    )
    return path, meta


def test_verified_tar_has_unicode_and_multiple_parts(tmp_path):
    path, meta = archive(tmp_path)
    assert cpe_feed.verify(path, meta) == 5
    assert list(cpe_feed.rows(path, meta)) == SAMPLE
    assert any(t["lang"] == "ja" for t in SAMPLE[-1]["cpe"]["titles"])
    assert {entry["cpe"]["cpeName"].split(":")[2] for entry in SAMPLE} == {"a", "o", "h"}


@pytest.mark.parametrize(
    "name,link", [("../escape.json", False), ("/tmp/install.json", False), (None, True)]
)
def test_unsafe_tar_member_is_rejected(tmp_path, name, link):
    path, meta = archive(tmp_path, path_override=name, link=link)
    with pytest.raises(cpe_feed.FeedError, match="FEED_TAR_MEMBER"):
        cpe_feed.verify(path, meta)


def test_invalid_digest_and_extraction_limit(tmp_path):
    path, meta = archive(tmp_path)
    with pytest.raises(cpe_feed.FeedError, match="FEED_INTEGRITY"):
        cpe_feed.verify(path, meta._replace(digest="0" * 64))
    with pytest.raises(cpe_feed.FeedError, match="FEED_JSON_SIZE"):
        cpe_feed.verify(path, meta._replace(json_bytes=meta.json_bytes - 1))


class Interrupted(httpx.SyncByteStream):
    def __init__(self, data):
        self.data = data

    def __iter__(self):
        yield self.data[: cpe_feed.CHUNK_BYTES]
        raise httpx.ReadError("simulated interruption")


def test_interrupted_download_resumes_exact_remaining_bytes(tmp_path):
    data = b"x" * 85000
    path = tmp_path / "download.part"
    meta = cpe_feed.FeedMeta("f" * 64, datetime.now(UTC), 104000, len(data))
    offsets = []

    def upstream(request):
        assert str(request.url) == cpe_feed.ARCHIVE_URL
        start = request.headers.get("Range")
        offsets.append(start)
        if start is None:
            return httpx.Response(200, stream=Interrupted(data))
        pos = cpe_feed.CHUNK_BYTES
        assert start == f"bytes={pos}-"
        return httpx.Response(
            206,
            content=data[pos:],
            headers={"content-range": f"bytes {pos}-{len(data) - 1}/{len(data)}"},
        )

    with httpx.Client(transport=httpx.MockTransport(upstream)) as client:
        with pytest.raises(httpx.ReadError):
            cpe_feed.download(client, path, meta)
        assert path.stat().st_size == cpe_feed.CHUNK_BYTES
        assert cpe_feed.download(client, path, meta) == len(data)
    assert path.read_bytes() == data and len(offsets) == 2


def test_range_must_match_checkpoint(tmp_path):
    path = tmp_path / "download.part"
    path.write_bytes(b"x")
    meta = cpe_feed.FeedMeta("f" * 64, datetime.now(UTC), 10, 10)
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(206, content=b"broken"))
    ) as client:
        with pytest.raises(cpe_feed.FeedError, match="FEED_RANGE"):
            cpe_feed.download(client, path, meta)
    assert path.read_bytes() == b"x"
