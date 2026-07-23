"""Public metadata helpers for immutable certificate deployments."""

from __future__ import annotations

import json
from datetime import datetime

from acme_api.deployer import DeploymentPaths


def generation_details(deployed: DeploymentPaths) -> dict[str, object] | None:
    """Read public immutable-generation metadata for certificate API output."""
    if deployed.generation_id is None:
        return None
    metadata = json.loads(deployed.metadata_path.read_text(encoding="utf-8"))
    return {
        "generation_id": deployed.generation_id,
        "paths": {
            "cert": str(deployed.cert_path),
            "chain": str(deployed.chain_path),
            "fullchain": str(deployed.fullchain_path),
            "privkey": str(deployed.privkey_path),
        },
        "fingerprint_sha256": metadata["fingerprint_sha256"],
        "serial": metadata.get("serial"),
        "subjects": metadata["subjects"],
        "validity": {"not_after": metadata["expires_at"]},
    }


def generation_expiry(deployed: DeploymentPaths) -> datetime | None:
    """Return the selected generation's persisted certificate expiry."""
    if deployed.generation_id is None:
        return None
    metadata = json.loads(deployed.metadata_path.read_text(encoding="utf-8"))
    return datetime.fromisoformat(metadata["expires_at"])
