"""
Unit tests for Phase 3: Docker compose specification, network isolation,
container hardening, and non-root Dockerfile enforcement.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import pytest
import yaml

REPO_DIR = Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = REPO_DIR / "docker-compose.yml"
SECCOMP_FILE = REPO_DIR / "security" / "seccomp.json"


@pytest.fixture(scope="module")
def compose_data() -> dict:
    assert COMPOSE_FILE.exists(), "docker-compose.yml must exist"
    with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data


class TestNetworkIsolation:
    """Verify network architecture and strict isolation between red and blue."""

    def test_internal_networks_defined(self, compose_data):
        networks = compose_data.get("networks", {})
        required_internal = ["red_net", "blue_net", "model_net", "audit_net"]
        for net in required_internal:
            assert net in networks, f"Network {net} must be defined"
            assert networks[net].get("internal") is True, f"Network {net} must have internal: true"

    def test_front_network_is_external(self, compose_data):
        networks = compose_data.get("networks", {})
        assert "front" in networks, "front network must be defined for dashboard"
        assert networks["front"].get("internal") is False, "front network must have internal: false"

    def test_red_and_blue_share_no_network(self, compose_data):
        services = compose_data.get("services", {})
        red_nets = set(services["red"].get("networks", []))
        blue_nets = set(services["blue"].get("networks", []))

        overlap = red_nets.intersection(blue_nets)
        assert not overlap, f"Red and Blue MUST NOT share any network! Shared: {overlap}"
        assert red_nets == {"red_net"}, f"Red should only connect to red_net, got: {red_nets}"
        assert blue_nets == {"blue_net"}, f"Blue should only connect to blue_net, got: {blue_nets}"

    def test_gateway_reaches_internal_networks_only(self, compose_data):
        services = compose_data.get("services", {})
        gw_nets = set(services["gateway"].get("networks", []))
        expected_gw_nets = {"red_net", "blue_net", "model_net", "audit_net"}
        assert gw_nets == expected_gw_nets, f"Gateway networks mismatch: {gw_nets}"
        assert "front" not in gw_nets, "Gateway must NOT attach to front network"

    def test_audit_and_llm_network_isolation(self, compose_data):
        services = compose_data.get("services", {})
        assert set(services["audit"].get("networks", [])) == {"audit_net"}
        assert set(services["llm"].get("networks", [])) == {"model_net"}

    def test_dashboard_network_attachments(self, compose_data):
        services = compose_data.get("services", {})
        dash_nets = set(services["dashboard"].get("networks", []))
        assert dash_nets == {"audit_net", "front"}


class TestVolumeIsolation:
    """Verify private volumes are partitioned and not shared across roles."""

    def test_volumes_declared(self, compose_data):
        volumes = compose_data.get("volumes", {})
        assert "red_payloads" in volumes, "red_payloads volume must be declared"
        assert "blue_rules" in volumes, "blue_rules volume must be declared"

    def test_red_payloads_not_mounted_in_blue(self, compose_data):
        services = compose_data.get("services", {})
        blue_vols = services["blue"].get("volumes", [])
        for vol in blue_vols:
            assert "red_payloads" not in str(vol), "Blue service must NOT mount red_payloads!"

    def test_blue_rules_not_mounted_in_red(self, compose_data):
        services = compose_data.get("services", {})
        red_vols = services["red"].get("volumes", [])
        for vol in red_vols:
            assert "blue_rules" not in str(vol), "Red service must NOT mount blue_rules!"


class TestHardeningConfiguration:
    """Verify AGENTS.md hardening constraints applied to every service."""

    def test_hardening_options_on_all_services(self, compose_data):
        services = compose_data.get("services", {})
        target_services = ["audit", "gateway", "red", "blue", "llm", "dashboard"]

        for sname in target_services:
            svc = services[sname]
            # 1. read_only
            assert svc.get("read_only") is True, f"{sname} must be read_only: true"
            # 2. tmpfs
            tmpfs = svc.get("tmpfs", [])
            assert "/tmp" in tmpfs, f"{sname} must mount tmpfs for /tmp"
            # 3. cap_drop ALL
            cap_drop = svc.get("cap_drop", [])
            assert "ALL" in cap_drop, f"{sname} must drop ALL capabilities"
            # 4. security_opt
            sec_opt = svc.get("security_opt", [])
            assert any("no-new-privileges:true" in opt for opt in sec_opt), (
                f"{sname} must have no-new-privileges:true"
            )
            assert any("seccomp" in opt for opt in sec_opt), (
                f"{sname} must reference seccomp profile"
            )
            # 5. Resource limits
            assert svc.get("pids_limit") is not None, f"{sname} must have pids_limit"
            assert svc.get("mem_limit") is not None, f"{sname} must have mem_limit"
            assert svc.get("cpus") is not None, f"{sname} must have cpus limit"
            # 6. No privileged or docker.sock
            assert svc.get("privileged") is not True, f"{sname} must NOT be privileged"
            vols = svc.get("volumes", [])
            for v in vols:
                assert "docker.sock" not in str(v), f"{sname} must NOT mount docker.sock"


class TestSeccompProfile:
    """Verify security/seccomp.json structure and blocked dangerous syscalls."""

    def test_seccomp_profile_valid(self):
        assert SECCOMP_FILE.exists(), "security/seccomp.json must exist"
        with open(SECCOMP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data.get("defaultAction") == "SCMP_ACT_ALLOW"
        arch_names = [a.get("architecture") for a in data.get("archMap", [])]
        assert "SCMP_ARCH_X86_64" in arch_names
        assert "SCMP_ARCH_AARCH64" in arch_names

        blocked = set()
        for rule in data.get("syscalls", []):
            if rule.get("action") == "SCMP_ACT_ERRNO":
                blocked.update(rule.get("names", []))

        critical_blocked = ["ptrace", "bpf", "reboot", "mount", "kexec_load", "pivot_root"]
        for call in critical_blocked:
            assert call in blocked, f"Seccomp profile must block {call}"


class TestDockerfilesNonRoot:
    """Verify all service Dockerfiles drop privileges and run as non-root."""

    @pytest.mark.parametrize(
        "service_name",
        ["audit", "gateway", "red", "blue", "llm", "dashboard"],
    )
    def test_dockerfile_has_non_root_user(self, service_name: str):
        dockerfile = REPO_DIR / "services" / service_name / "Dockerfile"
        assert dockerfile.exists(), f"Dockerfile for {service_name} must exist"
        content = dockerfile.read_text(encoding="utf-8")

        # Must have USER instruction
        user_matches = re.findall(r"^USER\s+(\S+)", content, re.MULTILINE)
        assert user_matches, f"{service_name} Dockerfile must declare a USER"
        last_user = user_matches[-1]
        assert last_user not in ["root", "0"], f"{service_name} USER cannot be root, got: {last_user}"

        # Must have groupadd/useradd or adduser
        assert (
            "useradd" in content or "adduser" in content
        ), f"{service_name} Dockerfile should create a dedicated non-root user"
