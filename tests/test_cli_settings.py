from __future__ import annotations

from glassbox import cli


def test_settings_reads_through_the_injected_plugin_getter():
    cli.set_config_getter(lambda key, default: {"network": True}.get(key, default))
    try:
        data = cli.settings()
        assert data["network"] is True
        assert data["allow_home"] is False
        assert data["audit"] is True
    finally:
        cli.set_config_getter(lambda key, default: default)
