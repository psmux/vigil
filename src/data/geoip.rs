//! GeoIP lookups — stub implementation with first-octet heuristic.
//!
//! TODO: Replace the heuristic with a real MaxMind MMDB database:
//!   static GEOIP_DB: &[u8] = include_bytes!("../../assets/GeoLite2-City.mmdb");
//!   let reader = maxminddb::Reader::from_source(GEOIP_DB).unwrap();

use std::net::IpAddr;

use crate::data::GeoLocation;

/// Look up the geographic location of an IP address.
///
/// Currently uses a rough first-octet heuristic for demo purposes.
/// Returns None for private/reserved IPs.
pub fn lookup(ip: IpAddr) -> Option<GeoLocation> {
    if is_private_ip(ip) {
        return None;
    }

    // Extract first octet for heuristic mapping
    let first_octet = match ip {
        IpAddr::V4(v4) => v4.octets()[0],
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // For mapped IPv4 (::ffff:x.x.x.x), use the IPv4 part
            if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                octets[12]
            } else {
                // Pure IPv6: rough mapping based on first byte
                octets[0]
            }
        }
    };

    // Rough mapping: first-octet ranges to countries (very approximate, for demo only)
    let (code, name, lat, lon) = match first_octet {
        1..=3 => ("US", "United States", 37.0902, -95.7129),
        4..=8 => ("US", "United States", 37.0902, -95.7129),
        12..=15 => ("US", "United States", 37.0902, -95.7129),
        17..=19 => ("US", "United States", 37.0902, -95.7129),
        20..=30 => ("US", "United States", 37.0902, -95.7129),
        31..=37 => ("NL", "Netherlands", 52.1326, 5.2913),
        38..=42 => ("FR", "France", 46.2276, 2.2137),
        43..=46 => ("JP", "Japan", 36.2048, 138.2529),
        47..=50 => ("CA", "Canada", 56.1304, -106.3468),
        51..=60 => ("DE", "Germany", 51.1657, 10.4515),
        61..=80 => ("AU", "Australia", -25.2744, 133.7751),
        81..=95 => ("GB", "United Kingdom", 55.3781, -3.436),
        96..=110 => ("CN", "China", 35.8617, 104.1954),
        111..=120 => ("IN", "India", 20.5937, 78.9629),
        121..=130 => ("KR", "South Korea", 35.9078, 127.7669),
        131..=140 => ("JP", "Japan", 36.2048, 138.2529),
        141..=155 => ("RU", "Russia", 61.524, 105.3188),
        156..=170 => ("BR", "Brazil", -14.235, -51.9253),
        171..=180 => ("DE", "Germany", 51.1657, 10.4515),
        181..=190 => ("BR", "Brazil", -14.235, -51.9253),
        191..=195 => ("NL", "Netherlands", 52.1326, 5.2913),
        196..=200 => ("ZA", "South Africa", -30.5595, 22.9375),
        201..=210 => ("BR", "Brazil", -14.235, -51.9253),
        211..=220 => ("KR", "South Korea", 35.9078, 127.7669),
        221..=230 => ("CN", "China", 35.8617, 104.1954),
        _ => ("XX", "Unknown", 0.0, 0.0),
    };

    Some(GeoLocation {
        country_code: code.to_string(),
        country_name: name.to_string(),
        city: None,
        latitude: lat,
        longitude: lon,
    })
}

/// Returns true if the IP is a private, loopback, link-local, or other reserved address.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                           // 127.0.0.0/8
                || v4.is_unspecified()                  // 0.0.0.0
                || v4.is_broadcast()                    // 255.255.255.255
                || v4.is_link_local()                   // 169.254.0.0/16
                || is_rfc1918(v4)                       // 10/8, 172.16/12, 192.168/16
                || is_shared_address(v4)                // 100.64.0.0/10 (CGNAT)
                || is_documentation(v4)                 // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || v4.is_multicast()                    // 224.0.0.0/4
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                            // ::1
                || v6.is_unspecified()                  // ::
                || v6.is_multicast()                    // ff00::/8
                || is_v6_link_local(v6)                 // fe80::/10
                || is_v6_unique_local(v6)               // fc00::/7
        }
    }
}

/// RFC 1918 private ranges: 10/8, 172.16/12, 192.168/16.
fn is_rfc1918(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}

/// Shared address space (CGNAT): 100.64.0.0/10.
fn is_shared_address(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// Documentation ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
fn is_documentation(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

/// IPv6 link-local: fe80::/10.
fn is_v6_link_local(ip: std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// IPv6 unique local: fc00::/7.
fn is_v6_unique_local(ip: std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    (octets[0] & 0xfe) == 0xfc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_private_ips() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_lookup_private_returns_none() {
        assert!(lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_none());
        assert!(lookup(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
    }

    #[test]
    fn test_lookup_public_returns_some() {
        let result = lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(result.is_some());
        let geo = result.unwrap();
        assert_eq!(geo.country_code, "US");
    }
}
