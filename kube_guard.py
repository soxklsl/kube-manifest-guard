"""Small offline Kubernetes policy gate; never contacts a cluster."""

import argparse
import json
from pathlib import Path

import yaml

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}


def audit(document, source="<memory>"):
    if not isinstance(document, dict):
        raise ValueError("Each YAML document must be an object")
    kind = document.get("kind")
    if kind == "List":
        return [f for item in document.get("items", []) for f in audit(item, source)]
    spec = document.get("spec") or {}
    if kind in WORKLOADS:
        spec = spec.get("template", {}).get("spec", {})
    elif kind == "CronJob":
        spec = (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )
    elif kind != "Pod":
        return []
    name = document.get("metadata", {}).get("name", "<unnamed>")
    findings = []

    def add(rule, target, message):
        findings.append(
            dict(
                source=source,
                resource=f"{kind}/{name}",
                target=target,
                rule=rule,
                message=message,
            )
        )

    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(field):
            add("host-namespace", "pod", f"{field} exposes host namespaces")
    for volume in spec.get("volumes", []):
        if "hostPath" in volume:
            add("host-path", volume.get("name", "?"), "Avoid hostPath volumes")
    pod_security = spec.get("securityContext") or {}
    for group in ("containers", "initContainers", "ephemeralContainers"):
        for container in spec.get(group, []):
            target = f"{group}/{container.get('name', '?')}"
            security = container.get("securityContext") or {}
            image = container.get("image", "")
            if "@sha256:" not in image:
                add("image-digest", target, "Pin an immutable image digest")
            if security.get("privileged"):
                add("privileged", target, "Disable privileged mode")
            if security.get("allowPrivilegeEscalation") is not False:
                add(
                    "privilege-escalation",
                    target,
                    "Set allowPrivilegeEscalation: false",
                )
            if (
                security.get("runAsNonRoot", pod_security.get("runAsNonRoot"))
                is not True
            ):
                add("non-root", target, "Set runAsNonRoot: true")
            if security.get("runAsUser", pod_security.get("runAsUser")) == 0:
                add("root-user", target, "runAsUser: 0 explicitly selects root")
            if security.get("readOnlyRootFilesystem") is not True:
                add("readonly-root", target, "Set readOnlyRootFilesystem: true")
            if group != "ephemeralContainers":
                resources = container.get("resources") or {}
                for scope in ("requests", "limits"):
                    if not all(
                        resources.get(scope, {}).get(key) for key in ("cpu", "memory")
                    ):
                        add("resources", target, f"Define cpu and memory {scope}")
    return findings


def scan(path):
    files = (
        sorted(set(path.rglob("*.yaml")) | set(path.rglob("*.yml")))
        if path.is_dir()
        else [path]
    )
    if not files:
        raise ValueError("No YAML files found")
    findings = []
    count = 0
    for file in files:
        for document in yaml.safe_load_all(file.read_text()):
            if document is not None:
                count += 1
                findings.extend(audit(document, str(file)))
    if not count:
        raise ValueError("No YAML documents found")
    return {"documents": count, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        report = scan(args.path)
    except (OSError, ValueError, yaml.YAMLError, TypeError, AttributeError) as error:
        parser.exit(2, f"Invalid input: {error}\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return int(bool(report["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
