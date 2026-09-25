from loglens import _quiet as _quiet
from loglens._version import __version__

_quiet.install()

__all__ = [
    "analyze",
    "analyze_async",
    "analyze_entries",
    "AnalysisResult",
    "Anomaly",
    "LiveDetector",
    "LogLensHandler",
    "RunConfig",
    "init",
    "Monitor",
    "SlackAlerter",
    "TeamsAlerter",
    "EmailAlerter",
    "AlertDispatcher",
    "__version__",
]

_LAZY = {
    "Anomaly": ("loglens.application.api", "Anomaly"),
    "AnalysisResult": ("loglens.application.api", "AnalysisResult"),
    "analyze": ("loglens.application.api", "analyze"),
    "analyze_async": ("loglens.application.api", "analyze_async"),
    "analyze_entries": ("loglens.application.api", "analyze_entries"),
    "LiveDetector": ("loglens.application.live", "LiveDetector"),
    "LogLensHandler": ("loglens.interface.handler", "LogLensHandler"),
    "RunConfig": ("loglens.detection.run", "RunConfig"),
    "init": ("loglens.interface.monitor", "init"),
    "Monitor": ("loglens.interface.monitor", "Monitor"),
    "SlackAlerter": ("loglens.infrastructure.alerts", "SlackAlerter"),
    "TeamsAlerter": ("loglens.infrastructure.alerts", "TeamsAlerter"),
    "EmailAlerter": ("loglens.infrastructure.alerts", "EmailAlerter"),
    "AlertDispatcher": ("loglens.infrastructure.alerts", "AlertDispatcher"),
}


def __getattr__(name):
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module 'loglens' has no attribute {name!r}")
    import importlib

    mod = importlib.import_module(target[0])
    return getattr(mod, target[1])


def __dir__():
    return sorted(__all__)
