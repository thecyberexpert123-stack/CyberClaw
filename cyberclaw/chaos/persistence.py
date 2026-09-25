"""Persist chaos reports only. This is not a second case, policy, or learning store."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from cyberclaw.chaos.models import ChaosReport
from cyberclaw.chaos.reports import render_text


class ChaosReportStore:
    """Writes diagnostic reports under a caller-supplied directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root) / "chaos-reports"
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, report: ChaosReport) -> Path:
        target = self.root / f"{report.scenario_id}.json"
        payload = report.model_dump(mode="json")
        text = json.dumps(payload, sort_keys=True, indent=2)
        tmp_name = None
        try:
            with NamedTemporaryFile("w", encoding="utf-8", dir=self.root, delete=False) as handle:
                tmp_name = handle.name
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, target)
        finally:
            if tmp_name and os.path.exists(tmp_name):
                os.unlink(tmp_name)
        (self.root / f"{report.scenario_id}.txt").write_text(render_text(report), encoding="utf-8")
        return target

    def load(self, scenario_id: str) -> ChaosReport:
        path = self.root / f"{scenario_id}.json"
        return ChaosReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
