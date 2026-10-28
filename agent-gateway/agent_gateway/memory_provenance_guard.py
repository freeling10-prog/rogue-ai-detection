"""Cross-session resource lineage and capability attenuation ledger."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Optional


ALL_CAPABILITIES_MASK: int = (1 << 64) - 1


def canonical_resource_id(resource_uri: str) -> str:
    """Return a canonical SHA-256 identifier for a resource URI or key."""
    if not isinstance(resource_uri, str) or not resource_uri.strip():
        raise ValueError("resource_uri must be a non-empty string")
    normalized = resource_uri.strip().replace("\\", "/")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProvenanceRecord:
    resource_hash: str
    writer_session_id: str
    taint_level: int
    capability_mask: int
    seq_num: int
    hmac_tag: str


@dataclass(frozen=True)
class ProvenanceCheckResult:
    allowed: bool
    verdict_code: str
    effective_taint: int
    effective_capability_mask: int
    writer_session_id: Optional[str] = None
    resource_hash: Optional[str] = None


class MemoryProvenanceGuard:
    """Tracks resource lineage across sessions using HMAC-signed records."""

    def __init__(self, hmac_key: bytes) -> None:
        if not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) == 0:
            raise ValueError("hmac_key must be non-empty bytes")
        self._key = bytes(hmac_key)
        self._ledger: Dict[str, ProvenanceRecord] = {}
        self._seq: int = 0

    def _compute_hmac(
        self,
        resource_hash: str,
        writer_session_id: str,
        taint_level: int,
        capability_mask: int,
        seq_num: int,
    ) -> str:
        payload = (
            f"{resource_hash}|{writer_session_id}|"
            f"{taint_level}|{capability_mask}|{seq_num}"
        ).encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _verify_record(self, record: ProvenanceRecord) -> bool:
        expected = self._compute_hmac(
            record.resource_hash,
            record.writer_session_id,
            record.taint_level,
            record.capability_mask,
            record.seq_num,
        )
        return hmac.compare_digest(expected, record.hmac_tag)

    def record_write(
        self,
        resource_uri: str,
        writer_session_id: str,
        taint_level: int,
        capability_mask: int = ALL_CAPABILITIES_MASK,
    ) -> ProvenanceRecord:
        """Record or monotonically ratchet lineage metadata for a resource."""
        if taint_level < 0:
            raise ValueError("taint_level must be non-negative")
        if not writer_session_id or not isinstance(writer_session_id, str):
            raise ValueError("writer_session_id must be a non-empty string")

        res_hash = canonical_resource_id(resource_uri)
        existing = self._ledger.get(res_hash)

        if existing is not None:
            if not self._verify_record(existing):
                raise ValueError("Existing provenance record failed HMAC check")
            merged_taint = max(existing.taint_level, taint_level)
            merged_caps = existing.capability_mask & (capability_mask & ALL_CAPABILITIES_MASK)
        else:
            merged_taint = taint_level
            merged_caps = capability_mask & ALL_CAPABILITIES_MASK

        self._seq += 1
        tag = self._compute_hmac(
            res_hash, writer_session_id, merged_taint, merged_caps, self._seq
        )
        record = ProvenanceRecord(
            resource_hash=res_hash,
            writer_session_id=writer_session_id,
            taint_level=merged_taint,
            capability_mask=merged_caps,
            seq_num=self._seq,
            hmac_tag=tag,
        )
        self._ledger[res_hash] = record
        return record

    def evaluate_read(
        self,
        resource_uri: str,
        reader_taint: int,
        reader_capability_mask: int = ALL_CAPABILITIES_MASK,
    ) -> ProvenanceCheckResult:
        """Verify HMAC integrity and propagate lineage bounds on resource read."""
        if reader_taint < 0:
            raise ValueError("reader_taint must be non-negative")
        res_hash = canonical_resource_id(resource_uri)
        record = self._ledger.get(res_hash)
        masked_reader_caps = reader_capability_mask & ALL_CAPABILITIES_MASK

        if record is None:
            return ProvenanceCheckResult(
                allowed=True,
                verdict_code="PROVENANCE_CLEAN",
                effective_taint=reader_taint,
                effective_capability_mask=masked_reader_caps,
                resource_hash=res_hash,
            )

        if not self._verify_record(record):
            return ProvenanceCheckResult(
                allowed=False,
                verdict_code="PROVENANCE_TAMPER_DENIED",
                effective_taint=max(reader_taint, 100),
                effective_capability_mask=0,
                writer_session_id=record.writer_session_id,
                resource_hash=res_hash,
            )

        effective_taint = max(reader_taint, record.taint_level)
        effective_caps = masked_reader_caps & record.capability_mask
        code = (
            "PROVENANCE_TAINT_INHERITED"
            if effective_taint > reader_taint or effective_caps != masked_reader_caps
            else "PROVENANCE_VERIFIED"
        )
        return ProvenanceCheckResult(
            allowed=True,
            verdict_code=code,
            effective_taint=effective_taint,
            effective_capability_mask=effective_caps,
            writer_session_id=record.writer_session_id,
            resource_hash=res_hash,
        )
