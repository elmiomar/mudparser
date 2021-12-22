"""
MudParser Interactive Demo Application.

A Streamlit-based web application for exploring MUD profiles.

Run with:
    streamlit run demo/streamlit_app.py

Or via CLI:
    mudparser demo
"""

import json
import sys
from pathlib import Path

import streamlit as st

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mudparser import MUDParser, __version__
from mudparser.exceptions import MUDParserError
from mudparser.exporters import ExportFormat
from mudparser.validator import MUDValidator, ValidationSeverity

# Page configuration
st.set_page_config(
    page_title="MudParser Demo",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 20px;
    }
    .validation-error {
        color: #ff4b4b;
        font-weight: bold;
    }
    .validation-warning {
        color: #ffa500;
    }
    .validation-info {
        color: #00a2ff;
    }
</style>
""", unsafe_allow_html=True)


def main():
    """Main application entry point."""
    st.title("🔒 MudParser Demo")
    st.markdown(f"*RFC 8520 & RFC 9761 Compliant MUD Profile Parser* — v{__version__}")

    # Sidebar
    with st.sidebar:
        st.header("📁 Load MUD Profile")

        load_method = st.radio(
            "Choose input method:",
            ["Upload File", "Paste JSON", "Sample Profile"],
            label_visibility="collapsed",
        )

        parser = None

        if load_method == "Upload File":
            uploaded_file = st.file_uploader(
                "Upload MUD JSON file",
                type=["json"],
                help="Upload a MUD profile in JSON format",
            )
            if uploaded_file:
                try:
                    content = uploaded_file.read().decode("utf-8")
                    parser = MUDParser.from_string(content, source=uploaded_file.name)
                    st.success(f"Loaded: {uploaded_file.name}")
                except MUDParserError as e:
                    st.error(f"Error: {e}")

        elif load_method == "Paste JSON":
            json_input = st.text_area(
                "Paste MUD JSON:",
                height=200,
                placeholder='{"ietf-mud:mud": {...}}',
            )
            if json_input:
                try:
                    parser = MUDParser.from_string(json_input, source="pasted")
                    st.success("JSON parsed successfully!")
                except MUDParserError as e:
                    st.error(f"Error: {e}")

        else:  # Sample Profile
            sample = get_sample_profile()
            parser = MUDParser.from_dict(sample, source="sample")
            st.info("Using sample Amazon Echo profile")

        st.divider()
        st.markdown("### About")
        st.markdown("""
        MudParser parses MUD (Manufacturer Usage Description) profiles
        that define network access policies for IoT devices.

        [Documentation](https://elmiomar.github.io/mudparser) |
        [GitHub](https://github.com/elmiomar/mudparser)
        """)

    # Main content
    if parser:
        display_profile(parser)
    else:
        st.info("👈 Load a MUD profile from the sidebar to get started.")
        display_instructions()


def display_profile(parser: MUDParser):
    """Display the parsed MUD profile."""
    # Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Overview",
        "🔍 Rules",
        "✅ Validation",
        "📤 Export",
        "📄 Raw JSON",
    ])

    with tab1:
        display_overview(parser)

    with tab2:
        display_rules(parser)

    with tab3:
        display_validation(parser)

    with tab4:
        display_export(parser)

    with tab5:
        display_json(parser)


def display_overview(parser: MUDParser):
    """Display profile overview."""
    st.header("Profile Overview")

    summary = parser.get_summary()

    # Device info
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Device Information")
        st.metric("Device Name", summary.get("systeminfo") or "Unknown")
        st.metric("Supported", "Yes" if summary["is_supported"] else "No")
        if summary.get("manufacturer"):
            st.metric("Manufacturer", summary["manufacturer"])

    with col2:
        st.subheader("MUD Metadata")
        st.metric("MUD Version", summary["version"])
        st.metric("Cache Validity", f"{summary['cache_validity_hours']} hours")
        st.text(f"URL: {summary['url']}")

    # Rules summary
    st.subheader("Access Control Summary")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Rules", summary["total_rules"])
    with col2:
        st.metric("From-Device (Outbound)", summary["from_device_rules"])
    with col3:
        st.metric("To-Device (Inbound)", summary["to_device_rules"])

    # Resources
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Referenced DNS Names")
        if summary["dns_names"]:
            for name in sorted(summary["dns_names"]):
                st.code(name)
        else:
            st.info("No DNS names referenced")

    with col2:
        st.subheader("Referenced Ports")
        if summary["ports"]["tcp"]:
            st.write(f"**TCP:** {', '.join(map(str, sorted(summary['ports']['tcp'])))}")
        if summary["ports"]["udp"]:
            st.write(f"**UDP:** {', '.join(map(str, sorted(summary['ports']['udp'])))}")
        if not summary["ports"]["tcp"] and not summary["ports"]["udp"]:
            st.info("No specific ports referenced")


def display_rules(parser: MUDParser):
    """Display access control rules."""
    st.header("Access Control Rules")

    # From-device rules
    st.subheader("📤 From-Device Policy (Outbound)")
    for acl in parser.get_from_device_acls():
        with st.expander(f"ACL: {acl.name} ({acl.acl_type.value})", expanded=True):
            for entry in acl.entries:
                display_ace(entry, "from")

    # To-device rules
    st.subheader("📥 To-Device Policy (Inbound)")
    for acl in parser.get_to_device_acls():
        with st.expander(f"ACL: {acl.name} ({acl.acl_type.value})", expanded=True):
            for entry in acl.entries:
                display_ace(entry, "to")


def display_ace(entry, direction: str):
    """Display a single ACE entry."""
    action_color = "green" if entry.is_accept() else "red"
    action_text = "ALLOW" if entry.is_accept() else "DENY"

    desc = entry.get_description(direction)

    st.markdown(f"""
    <div style="padding: 8px; background-color: #f0f2f6; border-radius: 4px; margin: 4px 0;">
        <span style="color: {action_color}; font-weight: bold;">[{action_text}]</span>
        <code>{entry.name}</code>
        <br/>
        <small>{desc}</small>
    </div>
    """, unsafe_allow_html=True)


def display_validation(parser: MUDParser):
    """Display validation results."""
    st.header("Validation Results")

    validator = MUDValidator()
    result = validator.validate(parser.profile)

    # Summary
    if result.is_valid:
        st.success("✅ Profile is valid!")
    else:
        st.error("❌ Profile validation failed")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Errors", result.error_count)
    with col2:
        st.metric("Warnings", result.warning_count)
    with col3:
        st.metric("Info", len(result.issues) - result.error_count - result.warning_count)

    # Issues list
    if result.issues:
        st.subheader("Issues Found")

        for issue in result.issues:
            if issue.severity == ValidationSeverity.ERROR:
                st.error(f"**ERROR:** {issue.message}")
            elif issue.severity == ValidationSeverity.WARNING:
                st.warning(f"**WARNING:** {issue.message}")
            else:
                st.info(f"**INFO:** {issue.message}")

            if issue.path:
                st.caption(f"Path: `{issue.path}`")


def display_export(parser: MUDParser):
    """Display export options."""
    st.header("Export Profile")

    col1, col2 = st.columns([1, 2])

    with col1:
        export_format = st.selectbox(
            "Export Format",
            [f.value for f in ExportFormat],
            format_func=lambda x: {
                "json": "JSON",
                "yaml": "YAML",
                "iptables": "iptables (Linux)",
                "nftables": "nftables (Linux)",
                "cisco": "Cisco IOS ACL",
                "pfsense": "pfSense XML",
            }.get(x, x),
        )

        # Device IP for firewall formats
        device_ip = None
        if export_format in ["iptables", "nftables", "pfsense"]:
            device_ip = st.text_input(
                "Device IP Address",
                value="192.168.1.100",
                help="Required for firewall rule generation",
            )

        export_button = st.button("Generate Export", type="primary")

    with col2:
        if export_button:
            try:
                kwargs = {}
                if device_ip:
                    kwargs["device_ip"] = device_ip

                output = parser.export.export(export_format, **kwargs)

                # Syntax highlighting
                lang_map = {
                    "json": "json",
                    "yaml": "yaml",
                    "iptables": "bash",
                    "nftables": "text",
                    "cisco": "text",
                    "pfsense": "xml",
                }

                st.code(output, language=lang_map.get(export_format, "text"))

                # Download button
                st.download_button(
                    label="📥 Download",
                    data=output,
                    file_name=f"mud_export.{export_format}",
                    mime="text/plain",
                )

            except Exception as e:
                st.error(f"Export error: {e}")


def display_json(parser: MUDParser):
    """Display raw JSON."""
    st.header("Raw JSON")

    json_str = parser.to_json(indent=2)
    st.code(json_str, language="json")

    st.download_button(
        label="📥 Download JSON",
        data=json_str,
        file_name="mud_profile.json",
        mime="application/json",
    )


def display_instructions():
    """Display getting started instructions."""
    st.header("Getting Started")

    st.markdown("""
    ### What is MUD?

    **MUD (Manufacturer Usage Description)** is an IETF standard (RFC 8520) that allows
    IoT device manufacturers to formally describe the network behavior their devices require.

    ### How to Use This Demo

    1. **Upload** a MUD profile JSON file, or
    2. **Paste** JSON content directly, or
    3. Use the built-in **sample profile**

    Then explore:
    - **Overview** - Device info and summary
    - **Rules** - Access control entries
    - **Validation** - RFC compliance check
    - **Export** - Generate firewall rules
    - **Raw JSON** - View the full profile

    ### Sample MUD Profile Structure

    ```json
    {
      "ietf-mud:mud": {
        "mud-version": 1,
        "mud-url": "https://example.com/device.json",
        "last-update": "2024-01-01T00:00:00Z",
        "cache-validity": 48,
        "is-supported": true,
        "systeminfo": "My IoT Device",
        "from-device-policy": { ... },
        "to-device-policy": { ... }
      },
      "ietf-access-control-list:access-lists": {
        "acl": [ ... ]
      }
    }
    ```
    """)


def get_sample_profile() -> dict:
    """Return a sample MUD profile for demo purposes."""
    return {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": "https://amazonecho.com/amazonecho",
            "last-update": "2024-01-15T00:00:00Z",
            "cache-validity": 48,
            "is-supported": True,
            "systeminfo": "Amazon Echo (Demo)",
            "from-device-policy": {
                "access-lists": {
                    "access-list": [
                        {"name": "from-ipv4-amazonecho"}
                    ]
                }
            },
            "to-device-policy": {
                "access-lists": {
                    "access-list": [
                        {"name": "to-ipv4-amazonecho"}
                    ]
                }
            },
        },
        "ietf-access-control-list:access-lists": {
            "acl": [
                {
                    "name": "from-ipv4-amazonecho",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "allow-https-amazon",
                                "matches": {
                                    "ipv4": {
                                        "protocol": 6,
                                        "ietf-acldns:dst-dnsname": "dcape-na.amazon.com"
                                    },
                                    "tcp": {
                                        "destination-port": {
                                            "operator": "eq",
                                            "port": 443
                                        }
                                    }
                                },
                                "actions": {"forwarding": "accept"}
                            },
                            {
                                "name": "allow-http-updates",
                                "matches": {
                                    "ipv4": {
                                        "protocol": 6,
                                        "ietf-acldns:dst-dnsname": "softwareupdates.amazon.com"
                                    },
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
                    "name": "to-ipv4-amazonecho",
                    "type": "ipv4-acl-type",
                    "aces": {
                        "ace": [
                            {
                                "name": "allow-https-response",
                                "matches": {
                                    "ipv4": {
                                        "protocol": 6,
                                        "ietf-acldns:src-dnsname": "dcape-na.amazon.com"
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


if __name__ == "__main__":
    main()
