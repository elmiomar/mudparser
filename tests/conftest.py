"""
Pytest configuration and fixtures for MudParser tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# Get the fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def amazon_echo_short_path(fixtures_dir: Path) -> Path:
    """Return the path to the short Amazon Echo MUD profile."""
    return fixtures_dir / "amazon_echo_short.json"


@pytest.fixture
def amazon_echo_full_path(fixtures_dir: Path) -> Path:
    """Return the path to the full Amazon Echo MUD profile."""
    return fixtures_dir / "amazon_echo.json"


@pytest.fixture
def mudmaker_path(fixtures_dir: Path) -> Path:
    """Return the path to the MUDMaker generated profile."""
    return fixtures_dir / "mudmaker_generated.json"


@pytest.fixture
def amazon_echo_short_data(amazon_echo_short_path: Path) -> dict[str, Any]:
    """Load the short Amazon Echo MUD profile as a dictionary."""
    with amazon_echo_short_path.open() as f:
        return json.load(f)


@pytest.fixture
def amazon_echo_short_json(amazon_echo_short_path: Path) -> str:
    """Load the short Amazon Echo MUD profile as a JSON string."""
    return amazon_echo_short_path.read_text()


@pytest.fixture
def minimal_mud_data() -> dict[str, Any]:
    """Create a minimal valid MUD profile."""
    return {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": "https://example.com/device.json",
            "last-update": "2024-01-01T00:00:00Z",
            "cache-validity": 48,
            "is-supported": True,
            "systeminfo": "Test Device",
            "from-device-policy": {
                "access-lists": {
                    "access-list": [{"name": "from-ipv4"}]
                }
            },
            "to-device-policy": {
                "access-lists": {
                    "access-list": [{"name": "to-ipv4"}]
                }
            },
        },
        "ietf-access-control-list:access-lists": {
            "acl": [
                {
                    "name": "from-ipv4",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "allow-https",
                                "matches": {
                                    "ipv4": {"protocol": 6},
                                    "tcp": {
                                        "destination-port": {
                                            "operator": "eq",
                                            "port": 443
                                        }
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            }
                        ]
                    }
                },
                {
                    "name": "to-ipv4",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "allow-established",
                                "matches": {
                                    "ipv4": {"protocol": 6},
                                    "tcp": {
                                        "source-port": {
                                            "operator": "eq",
                                            "port": 443
                                        }
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            }
                        ]
                    }
                }
            ]
        }
    }


@pytest.fixture
def invalid_mud_missing_container() -> dict[str, Any]:
    """Create an invalid MUD profile missing the MUD container."""
    return {
        "ietf-access-control-list:access-lists": {
            "acl": []
        }
    }


@pytest.fixture
def invalid_mud_bad_acl_reference() -> dict[str, Any]:
    """Create a MUD profile with an invalid ACL reference."""
    return {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": "https://example.com/device.json",
            "last-update": "2024-01-01T00:00:00Z",
            "cache-validity": 48,
            "is-supported": True,
            "from-device-policy": {
                "access-lists": {
                    "access-list": [{"name": "nonexistent-acl"}]
                }
            },
            "to-device-policy": {
                "access-lists": {
                    "access-list": []
                }
            },
        },
        "ietf-access-control-list:access-lists": {
            "acl": []
        }
    }


@pytest.fixture
def mud_with_all_match_types() -> dict[str, Any]:
    """Create a MUD profile with all match types."""
    return {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": "https://example.com/device.json",
            "last-update": "2024-01-01T00:00:00Z",
            "cache-validity": 48,
            "is-supported": True,
            "systeminfo": "Full Match Test",
            "from-device-policy": {
                "access-lists": {
                    "access-list": [
                        {"name": "from-ipv4"},
                        {"name": "from-eth"},
                    ]
                }
            },
            "to-device-policy": {
                "access-lists": {
                    "access-list": [{"name": "to-ipv4"}]
                }
            },
        },
        "ietf-access-control-list:access-lists": {
            "acl": [
                {
                    "name": "from-ipv4",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "tcp-with-dns",
                                "matches": {
                                    "ipv4": {
                                        "protocol": 6,
                                        "ietf-acldns:dst-dnsname": "api.example.com"
                                    },
                                    "tcp": {
                                        "destination-port": {
                                            "operator": "eq",
                                            "port": 443
                                        },
                                        "ietf-mud:direction-initiated": "from-device"
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            },
                            {
                                "name": "udp-rule",
                                "matches": {
                                    "ipv4": {"protocol": 17},
                                    "udp": {
                                        "destination-port": {
                                            "operator": "eq",
                                            "port": 53
                                        }
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            }
                        ]
                    }
                },
                {
                    "name": "from-eth",
                    "type": "ethernet-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "local-network",
                                "matches": {
                                    "ietf-mud:mud": {
                                        "local-networks": [None]
                                    },
                                    "eth": {
                                        "ethertype": "0x0800"
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            }
                        ]
                    }
                },
                {
                    "name": "to-ipv4",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "allow-established",
                                "matches": {
                                    "ipv4": {
                                        "protocol": 6,
                                        "ietf-acldns:src-dnsname": "api.example.com"
                                    },
                                    "tcp": {
                                        "source-port": {
                                            "operator": "eq",
                                            "port": 443
                                        }
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            }
                        ]
                    }
                }
            ]
        }
    }
