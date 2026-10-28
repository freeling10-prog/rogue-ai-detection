"""Cross-session resource lineage and capability attenuation ledger."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


ALL_CAPABILITIES_MASK: int = (1 << 64) - 1
MAX_TAINT_LEVEL: int = 100
LEDGER_SCHEMA: str = "agent-gateway.memory-provenance-ledger/1"


def _require_int(name: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int")
    return value


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
        """Record or monotonically ratchet lineage metadata for a resource.

        ``writer_session_id`` stays on the session that set the current taint
        level (or, at equal taint, last tightened the capability mask), so a
        later clean write does not replace the taint origin.
        """
        _require_int("taint_level", taint_level)
        _require_int("capability_mask", capability_mask)
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
            raised = taint_level > existing.taint_level
            tightened = taint_level == existing.taint_level and merged_caps != existing.capability_mask
            origin = writer_session_id if (raised or tightened) else existing.writer_session_id
        else:
            merged_taint = taint_level
            merged_caps = capability_mask & ALL_CAPABILITIES_MASK
            origin = writer_session_id

        self._seq += 1
        tag = self._compute_hmac(
            res_hash, origin, merged_taint, merged_caps, self._seq
        )
        record = ProvenanceRecord(
            resource_hash=res_hash,
            writer_session_id=origin,
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
        _require_int("reader_taint", reader_taint)
        _require_int("reader_capability_mask", reader_capability_mask)
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
                effective_taint=max(reader_taint, record.taint_level, MAX_TAINT_LEVEL),
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

    def export_ledger(self) -> dict:
        """Serializable copy of the ledger. Records keep their HMAC tags."""
        return {
            "schema": LEDGER_SCHEMA,
            "seq": self._seq,
            "records": [asdict(r) for r in sorted(self._ledger.values(), key=lambda r: r.seq_num)],
        }

    def load_ledger(self, data: dict) -> None:
        """Replace the ledger with ``data`` after verifying every record.

        All or nothing: any malformed, duplicated, or HMAC-invalid entry raises
        ``ValueError`` and leaves the current ledger unchanged.
        """
        if not isinstance(data, dict) or data.get("schema") != LEDGER_SCHEMA:
            raise ValueError("unknown ledger schema")
        records = data.get("records")
        seq = data.get("seq", 0)
        if not isinstance(records, list) or not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise ValueError("malformed ledger")
        fields = ("resource_hash", "writer_session_id", "taint_level", "capability_mask", "seq_num", "hmac_tag")
        loaded: Dict[str, ProvenanceRecord] = {}
        for i, raw in enumerate(records):
            if not isinstance(raw, dict) or set(raw) != set(fields):
                raise ValueError(f"record {i}: unexpected fields")
            try:
                record = ProvenanceRecord(
                    resource_hash=str(raw["resource_hash"]),
                    writer_session_id=str(raw["writer_session_id"]),
                    taint_level=_require_int("taint_level", raw["taint_level"]),
                    capability_mask=_require_int("capability_mask", raw["capability_mask"]),
                    seq_num=_require_int("seq_num", raw["seq_num"]),
                    hmac_tag=str(raw["hmac_tag"]),
                )
            except TypeError as exc:
                raise ValueError(f"record {i}: {exc}") from None
            if record.resource_hash in loaded:
                raise ValueError(f"record {i}: duplicate resource_hash")
            if not self._verify_record(record):
                raise ValueError(f"record {i}: HMAC check failed")
            loaded[record.resource_hash] = record
        self._ledger = loaded
        self._seq = max([seq, *(r.seq_num for r in loaded.values())])
