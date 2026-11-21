"""Qualys TAP plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name); nothing is authored here (req-tap-plugin-manifest-v0-scaffold).
The live collector registers in ``ready()`` (req-qualys-detection-read).
"""

from tap_plugins.base import TapPluginConfig


class QualysConfig(TapPluginConfig):
    def ready(self) -> None:
        super().ready()

        # Inside ready(), not at module top, so loading the app stays light.
        from tap_cares.registry import register_collector

        from tap_plugin.qualys.collectors.qualys_collector import QualysCollector

        register_collector(
            key="qualys",
            cls=QualysCollector,
            scope="qualys",
            name="Qualys",
            description="Reads host detections and their knowledge-base records from every configured Qualys subscription, through a transport that sends only allowlisted GET requests.",
        )
