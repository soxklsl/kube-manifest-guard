import pytest

from kube_guard import audit, scan


def good():
    return {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": True},
            "containers": [
                {
                    "name": "api",
                    "image": "example@sha256:" + "a" * 64,
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                    },
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "64Mi"},
                        "limits": {"cpu": "1", "memory": "128Mi"},
                    },
                }
            ],
        },
    }


def test_good():
    assert audit(good()) == []


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet", "DaemonSet", "Job"])
def test_workloads(kind):
    assert audit({"kind": kind, "spec": {"template": {"spec": good()["spec"]}}}) == []


def test_root_override_and_init():
    pod = good()
    pod["spec"]["initContainers"] = [
        {"name": "init", "securityContext": {"runAsUser": 0}}
    ]
    rules = {f["rule"] for f in audit(pod)}
    assert {"root-user", "image-digest", "privilege-escalation"} <= rules


def test_cronjob_and_list():
    doc = {
        "kind": "CronJob",
        "spec": {"jobTemplate": {"spec": {"template": {"spec": good()["spec"]}}}},
    }
    assert audit({"kind": "List", "items": [doc]}) == []


def test_multidoc(tmp_path):
    path = tmp_path / "input.yaml"
    path.write_text("kind: Service\n---\nkind: Pod\nspec:\n  hostPID: true\n")
    assert len(scan(path)["findings"]) == 1


def test_empty_directory(tmp_path):
    with pytest.raises(ValueError):
        scan(tmp_path)


def test_invalid():
    with pytest.raises(ValueError):
        audit(["bad"])
