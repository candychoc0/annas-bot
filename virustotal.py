import asyncio
import hashlib
import logging
import os

import httpx

logger = logging.getLogger(__name__)

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
VT_MAX_SIZE = 32 * 1024 * 1024  # 32 MB — free tier upload limit


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


async def scan_file(file_path: str) -> dict | None:
    """
    Scan a file with VirusTotal. Returns stats dict or None if VT disabled or file too large.
    Stats keys: malicious, suspicious, undetected, harmless, timeout, failure, type-unsupported.
    """
    if not VT_API_KEY:
        return None

    size = os.path.getsize(file_path)
    if size > VT_MAX_SIZE:
        logger.info(f"VirusTotal: file too large ({size / 1024 / 1024:.1f} MB), skipping scan")
        return None

    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient(headers=headers) as client:
        # Check by hash first — avoids a redundant upload if VT already knows the file
        sha256 = await asyncio.get_event_loop().run_in_executor(None, _sha256, file_path)
        resp = await client.get(f"{VT_BASE}/files/{sha256}", timeout=15)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            logger.info(f"VirusTotal: existing report for {sha256[:12]}… — {stats}")
            return stats

        # Not yet known — upload the file
        logger.info(f"VirusTotal: uploading file ({size / 1024 / 1024:.1f} MB)…")
        with open(file_path, "rb") as f:
            resp = await client.post(
                f"{VT_BASE}/files",
                files={"file": (os.path.basename(file_path), f)},
                timeout=120,
            )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        # Poll until analysis is complete (up to 90 s)
        for _ in range(18):
            await asyncio.sleep(5)
            resp = await client.get(f"{VT_BASE}/analyses/{analysis_id}", timeout=15)
            resp.raise_for_status()
            data = resp.json()["data"]
            if data["attributes"]["status"] == "completed":
                stats = data["attributes"]["stats"]
                logger.info(f"VirusTotal: analysis complete — {stats}")
                return stats

    raise TimeoutError("VirusTotal analysis timed out after 90 s")
