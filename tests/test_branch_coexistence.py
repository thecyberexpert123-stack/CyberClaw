"""Tests verifying architectural coexistence of branching with OSINT, Network, Planner, and unknown future specialists."""

import pytest
from cyberclaw.branching.engine import BranchEngine
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.types import Source


def test_branching_coexistence_with_osint_network_and_future_specialist():
    """Verify branching operates without domain conditionals across OSINT, Network, and unknown future specialists."""
    inv = Investigation(title="Coexistence Investigation", description="Testing multi-domain branching")
    inv.dfa.transition(CoreState.READY, event="init_complete")
    inv.case_manager.record_state_transition("INITIALIZE", "READY", "init_complete")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start_investigation")
    inv.case_manager.record_state_transition("READY", "INVESTIGATE", "start_investigation")

    # Ingest OSINT baseline
    ev_osint = Evidence(
        type="dns_record",
        subject="ground-c2.net",
        value={"ip": "203.0.113.88"},
        source=Source(type="osint", name="DNSProvider"),
    )
    inv.add_evidence(ev_osint)
    inv.add_entity("domain", "ground-c2.net")

    # Ingest Network baseline
    ev_net = Evidence(
        type="port_scan_result",
        subject="203.0.113.88",
        value={"open_ports": [443, 8080]},
        source=Source(type="network", name="PortScanner"),
    )
    inv.add_evidence(ev_net)
    inv.add_entity("ip", "203.0.113.88")

    inv.capture_snapshot(trigger="multi_domain_recon")

    # Branch exploring future satellite capability
    branch_sat = inv.create_branch(
        source_snapshot=1,
        purpose="Explore hypothetical orbital telemetry downlink",
    )

    ev_sat = Evidence(
        type="satellite_downlink_telemetry",
        subject="SAT-OBS-48211",
        value={"downlink_freq_mhz": 2245.5},
        source=Source(type="future_satellite", name="ground_station_alpha"),
    )
    BranchEngine.simulate_evidence(branch_sat, [ev_sat])

    # Replay branch
    recon = inv.replay_branch(branch_sat.branch_id)
    assert len(recon.evidence) == 3  # OSINT + Network + Satellite
    assert any(e.type == "satellite_downlink_telemetry" for e in recon.evidence)
    assert any(e.type == "dns_record" for e in recon.evidence)
    assert any(e.type == "port_scan_result" for e in recon.evidence)

    # Core investigation still only has OSINT + Network
    assert len(inv.evidence_store.list_all()) == 2
