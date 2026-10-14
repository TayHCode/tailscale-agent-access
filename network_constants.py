"""Public protocol ranges, shared by validation and offline regression tests."""

from ipaddress import ip_network

RFC1918_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)
TAILSCALE_CGNAT_NETWORK = ip_network("100.64.0.0/10")
TAILSCALE_IPV6_NETWORK = ip_network("fd7a:115c:a1e0::/48")
IPV6_ULA_NETWORK = ip_network("fc00::/7")
