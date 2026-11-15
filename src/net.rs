use crate::metrics::Metrics;
use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

/// Detect the real outbound LAN IPv4 address (connecting to the default gateway / internet)
/// instead of virtual adapters like Tailscale (`100.x.y.z`) or VMware (`192.168.x.x`).
pub fn detect_local_ip() -> IpAddr {
    // 1. First try a UDP routing probe toward standard router gateways or public DNS.
    // Note: UDP `connect` does not send any packets on the wire; it just asks the OS routing table
    // which source IP routes to the target!
    let probe_targets = [
        "192.168.1.254:80",
        "192.168.1.1:80",
        "192.168.0.254:80",
        "192.168.0.1:80",
        "1.1.1.1:80",
        "8.8.8.8:80",
    ];

    for target in probe_targets {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(local_addr) = sock.local_addr() {
                    let ip = local_addr.ip();
                    if is_lan_ipv4(&ip) {
                        return ip;
                    }
                }
            }
        }
    }

    // 2. Fallback: enumerate all interfaces and pick a private RFC1918 LAN IP (skipping Tailscale CGNAT 100.64.0.0/10)
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in &ifaces {
            let lower = name.to_lowercase();
            if lower.contains("tailscale")
                || lower.contains("vmware")
                || lower.contains("vmnet")
                || lower.contains("vethernet")
                || lower.contains("wsl")
                || lower.contains("bluetooth")
            {
                continue;
            }
            if is_lan_ipv4(ip) {
                return *ip;
            }
        }
    }

    local_ip_address::local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

fn is_lan_ipv4(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Reject loopback (127.x) and Tailscale/CGNAT (100.64.0.0/10)
            if v4.is_loopback() || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) {
                return false;
            }
            v4.is_private()
        }
        IpAddr::V6(_) => false,
    }
}

pub struct UpnpLease {
    pub external_port: u16,
    pub local_addr: SocketAddrV4,
}

impl UpnpLease {
    pub async fn release(&self, metrics: &Arc<Metrics>) {
        if let Ok(gateway) = discover_gateway(self.local_addr.ip()).await {
            let _ = gateway
                .remove_port(PortMappingProtocol::TCP, self.external_port)
                .await;
            metrics.log(format!(
                "UPnP: Removed port mapping for TCP port {}",
                self.external_port
            ));
        }
    }
}

/// Discover UPnP IGD gateway bound explicitly to the LAN interface IP (so the OS doesn't route
/// SSDP multicast out of virtual/VPN adapters), trying both multicast and direct gateway unicast.
async fn discover_gateway(local_v4: &Ipv4Addr) -> Result<Gateway<Tokio>, igd_next::SearchError> {
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(*local_v4, 0));

    // 1. Standard SSDP multicast bound explicitly to our LAN NIC
    let multicast_opts = SearchOptions {
        bind_addr,
        timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    };
    if let Ok(gw) = search_gateway(multicast_opts).await {
        return Ok(gw);
    }

    // 2. Direct unicast SSDP to the subnet's `.254` or `.1` gateway on port 1900
    let octets = local_v4.octets();
    for last_octet in [254u8, 1u8] {
        let gw_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet);
        let unicast_opts = SearchOptions {
            bind_addr,
            broadcast_address: SocketAddr::V4(SocketAddrV4::new(gw_ip, 1900)),
            timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        if let Ok(gw) = search_gateway(unicast_opts).await {
            return Ok(gw);
        }
    }

    // 3. Final fallback with default options
    search_gateway(SearchOptions {
        timeout: Some(Duration::from_secs(2)),
        ..Default::default()
    })
    .await
}

pub async fn setup_upnp_and_public_ip(
    local_ip: IpAddr,
    port: u16,
    enable_upnp: bool,
    metrics: Arc<Metrics>,
) -> Option<UpnpLease> {
    let mut found_public_ip: Option<String> = None;
    let mut lease: Option<UpnpLease> = None;

    if enable_upnp {
        metrics.update_upnp(
            None,
            format!("Searching for UPnP gateway on {}...", local_ip),
        );

        let local_v4 = match local_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                metrics.update_upnp(None, "IPv6 local address (UPnP IGD requires IPv4)");
                return None;
            }
        };

        match discover_gateway(&local_v4).await {
            Ok(gateway) => {
                if let Ok(ext_ip) = gateway.get_external_ip().await {
                    found_public_ip = Some(ext_ip.to_string());
                }

                let local_sock = SocketAddrV4::new(local_v4, port);
                // Try a 3600s lease first; if the router requires permanent leases (0), retry with 0.
                let mut map_res = gateway
                    .add_port(
                        PortMappingProtocol::TCP,
                        port,
                        SocketAddr::V4(local_sock),
                        3600,
                        "fastshare-10g",
                    )
                    .await;

                if map_res.is_err() {
                    map_res = gateway
                        .add_port(
                            PortMappingProtocol::TCP,
                            port,
                            SocketAddr::V4(local_sock),
                            0,
                            "fastshare-10g",
                        )
                        .await;
                }

                match map_res {
                    Ok(()) => {
                        let status = format!("UPnP Active via {} (TCP {} -> {})", gateway.addr.ip(), port, local_sock);
                        metrics.log(format!(
                            "UPnP: Mapped external TCP port {} to {} via gateway {}",
                            port, local_sock, gateway.addr
                        ));
                        metrics.update_upnp(found_public_ip.clone(), status);
                        lease = Some(UpnpLease {
                            external_port: port,
                            local_addr: local_sock,
                        });
                    }
                    Err(e) => {
                        let status = format!(
                            "UPnP Port Map Failed ({}) - Check port range / manual forward",
                            e
                        );
                        metrics.log(format!("UPnP warning: {}", status));
                        metrics.update_upnp(found_public_ip.clone(), status);
                    }
                }
            }
            Err(e) => {
                let status = format!("No UPnP gateway ({}) - Use manual port forward", e);
                metrics.log(format!("UPnP: {}", status));
                metrics.update_upnp(None, status);
            }
        }
    } else {
        metrics.update_upnp(None, "Disabled (--no-upnp)");
    }

    // Fallback: if UPnP didn't give us a public IP, query a lightweight HTTP IP echo
    if found_public_ip.is_none() {
        if let Some(ip) = fetch_public_ip_http().await {
            let current_status = metrics
                .net_info
                .read()
                .map(|i| i.upnp_status.clone())
                .unwrap_or_default();
            metrics.log(format!("Detected public IP: {}", ip));
            metrics.update_upnp(Some(ip), current_status);
        }
    }

    lease
}

/// Lightweight HTTP/1.1 query to checkip.amazonaws.com / api.ipify.org without needing TLS dependencies
async fn fetch_public_ip_http() -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let endpoints = [
        ("api.ipify.org:80", "api.ipify.org"),
        ("checkip.amazonaws.com:80", "checkip.amazonaws.com"),
        ("icanhazip.com:80", "icanhazip.com"),
    ];

    for (addr, host) in endpoints {
        let connect_fut = TcpStream::connect(addr);
        if let Ok(Ok(mut stream)) = tokio::time::timeout(Duration::from_secs(2), connect_fut).await {
            let req = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: fastshare/0.1\r\nConnection: close\r\n\r\n",
                host
            );
            if stream.write_all(req.as_bytes()).await.is_ok() {
                let mut buf = Vec::with_capacity(512);
                if tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
                    .await
                    .is_ok()
                {
                    if let Ok(text) = std::str::from_utf8(&buf) {
                        if let Some(body) = text.split("\r\n\r\n").nth(1) {
                            let trimmed = body.trim();
                            if trimmed.parse::<IpAddr>().is_ok() {
                                return Some(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
