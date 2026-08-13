"""SentinelX core agent."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sentinelx-cloud-core")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

AGENT_VERSION = __version__
