from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path


ROOT = Path("/home/guru/Dev/MITHack")


class FakeFastAPI:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def middleware(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def get(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def post(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def on_event(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator


class FakeHTTPException(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class FakeBaseModel:
    def __init__(self, **kwargs) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)


class DummyEstimator:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def fit(self, *args, **kwargs):
        return self

    def predict(self, matrix):
        return ["unknown_anomaly" for _ in matrix]

    def decision_function(self, matrix):
        return [0.0 for _ in matrix]


def _module(name: str, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def install_test_stubs() -> None:
    async def async_notify(*args, **kwargs):
        return []

    services_module = sys.modules.setdefault("services", _module("services"))
    services_module.__path__ = [str(ROOT / "services")]

    shared_module = sys.modules.setdefault("services.shared", _module("services.shared"))
    shared_module.__path__ = [str(ROOT / "services" / "shared")]

    observability = _module(
        "services.shared.observability",
        install_observability=lambda app, service_name: logging.getLogger(f"test.{service_name}"),
        observe_event=lambda *args, **kwargs: None,
        traced_get=lambda client, url, **kwargs: client.get(url, **kwargs),
        traced_post=lambda client, url, **kwargs: client.post(url, **kwargs),
    )
    sys.modules["services.shared.observability"] = observability

    audit = _module(
        "services.shared.audit",
        audit_event=lambda *args, **kwargs: None,
        recent_audit_events=lambda *args, **kwargs: [],
    )
    sys.modules["services.shared.audit"] = audit

    history = _module(
        "services.shared.history",
        record_history=lambda *args, **kwargs: None,
        recent_history=lambda *args, **kwargs: [],
    )
    sys.modules["services.shared.history"] = history

    auth = _module(
        "services.shared.auth",
        ROLE_OPERATOR="operator",
        ROLE_ADMIN="admin",
        bearer_principal_and_role=lambda authorization: (None, None),
    )
    sys.modules["services.shared.auth"] = auth

    notifications = _module(
        "services.shared.notifications",
        notify=async_notify,
        should_notify=lambda *args, **kwargs: False,
        notification_worker=async_notify,
    )
    sys.modules["services.shared.notifications"] = notifications

    migrations = _module("services.shared.migrations", migrate=lambda: None)
    sys.modules["services.shared.migrations"] = migrations

    maintenance = _module("services.shared.maintenance", prune_tables=lambda *args, **kwargs: None)
    sys.modules["services.shared.maintenance"] = maintenance

    fastapi = _module(
        "fastapi",
        FastAPI=FakeFastAPI,
        HTTPException=FakeHTTPException,
        Request=object,
        Query=lambda default=None, **kwargs: default,
    )
    sys.modules["fastapi"] = fastapi

    fastapi_responses = _module(
        "fastapi.responses",
        HTMLResponse=str,
        StreamingResponse=object,
        Response=object,
    )
    sys.modules["fastapi.responses"] = fastapi_responses

    pydantic = _module("pydantic", BaseModel=FakeBaseModel)
    sys.modules["pydantic"] = pydantic

    httpx = _module(
        "httpx",
        AsyncClient=object,
        Client=object,
    )
    sys.modules["httpx"] = httpx

    numpy = _module("numpy", array=lambda value: value)
    sys.modules["numpy"] = numpy

    sklearn = _module("sklearn")
    sklearn.__path__ = []
    sklearn_ensemble = _module("sklearn.ensemble", IsolationForest=DummyEstimator)
    sklearn_tree = _module("sklearn.tree", DecisionTreeClassifier=DummyEstimator)
    sys.modules["sklearn"] = sklearn
    sys.modules["sklearn.ensemble"] = sklearn_ensemble
    sys.modules["sklearn.tree"] = sklearn_tree

    joblib = _module("joblib", dump=lambda *args, **kwargs: None, load=lambda *args, **kwargs: DummyEstimator())
    sys.modules["joblib"] = joblib

    jwt = _module("jwt", decode=lambda token, **kwargs: {})
    sys.modules["jwt"] = jwt

    yaml = _module("yaml", safe_load=lambda raw: {})
    sys.modules["yaml"] = yaml

    kubernetes = _module("kubernetes")
    kubernetes.__path__ = []
    kubernetes_client = _module(
        "kubernetes.client",
        V1Container=object,
        AppsV1Api=object,
        CoreV1Api=object,
        NetworkingV1Api=object,
        BatchV1Api=object,
        V1NetworkPolicy=object,
        V1ObjectMeta=object,
        V1NetworkPolicySpec=object,
        V1LabelSelector=object,
        V1Job=object,
        V1JobSpec=object,
        V1PodTemplateSpec=object,
        V1PodSpec=object,
        V1ResourceRequirements=object,
    )
    kubernetes_config = _module(
        "kubernetes.config",
        load_incluster_config=lambda: None,
        load_kube_config=lambda: None,
    )
    sys.modules["kubernetes"] = kubernetes
    sys.modules["kubernetes.client"] = kubernetes_client
    sys.modules["kubernetes.config"] = kubernetes_config


def load_module(relative_path: str, name: str):
    install_test_stubs()
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module
