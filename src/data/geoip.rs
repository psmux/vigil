//! GeoIP lookups using embedded DB-IP Lite MMDB database.
//!
//! The ~7 MB DB-IP Lite country database is compiled into the binary via
//! `include_bytes!()`, giving accurate country-level lookups with zero
//! runtime file dependencies.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use maxminddb::Reader;
use serde::Deserialize;

use crate::data::GeoLocation;

// ─── Embedded database ─────────────────────────────────────────────

static DB_BYTES: &[u8] = include_bytes!("../../assets/dbip-country-lite.mmdb");

static DB: OnceLock<Option<Reader<&'static [u8]>>> = OnceLock::new();

fn get_reader() -> &'static Option<Reader<&'static [u8]>> {
    DB.get_or_init(|| {
        Reader::from_source(DB_BYTES)
            .inspect_err(|e| eprintln!("geoip: failed to load MMDB: {e}"))
            .ok()
    })
}

// ─── MMDB deserialization structs ──────────────────────────────────

#[derive(Deserialize, Debug)]
struct DbIpCountry {
    country: Option<CountryRecord>,
}

#[derive(Deserialize, Debug)]
struct CountryRecord {
    iso_code: Option<String>,
    names: Option<HashMap<String, String>>,
}

// ─── Public API ────────────────────────────────────────────────────

/// Look up the geographic location of an IP address.
///
/// Uses the embedded DB-IP Lite MMDB for accurate country-level resolution.
/// Returns `None` for private/reserved IPs or if the IP is not in the database.
pub fn lookup(ip: IpAddr) -> Option<GeoLocation> {
    if is_private_ip(ip) {
        return None;
    }

    let reader = get_reader().as_ref()?;
    let result: DbIpCountry = reader.lookup(ip).ok()?;
    let country = result.country?;
    let code = country.iso_code.unwrap_or_default();

    if code.is_empty() {
        return None;
    }

    // Try to get the English name from the MMDB, fall back to our own table
    let name = country
        .names
        .as_ref()
        .and_then(|m| m.get("en").cloned())
        .unwrap_or_else(|| country_name(&code).to_string());

    // Look up approximate center coordinates for the country
    let (lat, lon) = country_center(&code).unwrap_or((0.0, 0.0));

    Some(GeoLocation {
        country_code: code,
        country_name: name,
        city: None,
        latitude: lat,
        longitude: lon,
    })
}

// ─── Country center coordinates ────────────────────────────────────
//
// Approximate geographic center (lat, lon) for common countries.
// Used to place dots on the braille world map.

fn country_center(code: &str) -> Option<(f64, f64)> {
    Some(match code {
        "AD" => (42.5, 1.5),
        "AE" => (24.0, 54.0),
        "AF" => (33.0, 65.0),
        "AG" => (17.0, -61.8),
        "AL" => (41.0, 20.0),
        "AM" => (40.0, 45.0),
        "AO" => (-12.5, 18.5),
        "AR" => (-34.0, -64.0),
        "AT" => (47.3, 13.3),
        "AU" => (-25.0, 134.0),
        "AZ" => (40.5, 47.5),
        "BA" => (44.0, 17.8),
        "BB" => (13.2, -59.5),
        "BD" => (24.0, 90.0),
        "BE" => (50.8, 4.0),
        "BF" => (12.3, -1.5),
        "BG" => (42.7, 25.5),
        "BH" => (26.0, 50.5),
        "BI" => (-3.4, 29.9),
        "BJ" => (9.3, 2.3),
        "BN" => (4.9, 114.9),
        "BO" => (-17.0, -65.0),
        "BR" => (-14.2, -51.9),
        "BS" => (25.0, -77.4),
        "BT" => (27.5, 90.4),
        "BW" => (-22.3, 24.7),
        "BY" => (53.7, 27.9),
        "BZ" => (17.2, -88.5),
        "CA" => (56.1, -106.3),
        "CD" => (-4.0, 21.8),
        "CF" => (6.6, 20.9),
        "CG" => (-0.2, 15.8),
        "CH" => (46.8, 8.2),
        "CI" => (7.5, -5.5),
        "CL" => (-33.4, -70.6),
        "CM" => (6.0, 12.0),
        "CN" => (35.9, 104.2),
        "CO" => (4.6, -74.1),
        "CR" => (10.0, -84.0),
        "CU" => (21.5, -80.0),
        "CY" => (35.1, 33.4),
        "CZ" => (49.8, 15.5),
        "DE" => (51.2, 10.5),
        "DJ" => (11.6, 43.1),
        "DK" => (56.3, 9.5),
        "DO" => (18.7, -70.2),
        "DZ" => (28.0, 1.7),
        "EC" => (-1.8, -78.2),
        "EE" => (58.6, 25.0),
        "EG" => (27.0, 30.0),
        "ER" => (15.2, 39.8),
        "ES" => (40.5, -3.7),
        "ET" => (9.1, 40.5),
        "FI" => (64.0, 26.0),
        "FJ" => (-18.0, 175.0),
        "FR" => (46.2, 2.2),
        "GA" => (-0.8, 11.6),
        "GB" => (55.4, -3.4),
        "GE" => (42.3, 43.4),
        "GH" => (7.9, -1.0),
        "GM" => (13.4, -16.6),
        "GN" => (9.9, -9.7),
        "GQ" => (1.6, 10.3),
        "GR" => (39.1, 21.8),
        "GT" => (15.8, -90.2),
        "GW" => (12.0, -15.0),
        "GY" => (5.0, -59.0),
        "HK" => (22.4, 114.1),
        "HN" => (14.6, -86.2),
        "HR" => (45.1, 15.2),
        "HT" => (19.0, -72.4),
        "HU" => (47.2, 19.5),
        "ID" => (-2.0, 118.0),
        "IE" => (53.4, -8.2),
        "IL" => (31.0, 35.0),
        "IN" => (20.6, 78.9),
        "IQ" => (33.2, 43.7),
        "IR" => (32.4, 53.7),
        "IS" => (65.0, -18.0),
        "IT" => (42.8, 12.6),
        "JM" => (18.1, -77.3),
        "JO" => (31.0, 36.0),
        "JP" => (36.2, 138.3),
        "KE" => (-1.0, 38.0),
        "KG" => (41.2, 74.8),
        "KH" => (12.6, 105.0),
        "KP" => (40.3, 127.5),
        "KR" => (35.9, 127.8),
        "KW" => (29.3, 47.5),
        "KZ" => (48.0, 68.0),
        "LA" => (19.9, 102.5),
        "LB" => (33.9, 35.9),
        "LK" => (7.9, 80.8),
        "LR" => (6.4, -9.4),
        "LS" => (-29.6, 28.2),
        "LT" => (55.2, 23.9),
        "LU" => (49.8, 6.1),
        "LV" => (56.9, 24.1),
        "LY" => (26.3, 17.2),
        "MA" => (31.8, -7.1),
        "MD" => (47.4, 28.4),
        "ME" => (42.7, 19.4),
        "MG" => (-18.8, 46.9),
        "MK" => (41.5, 21.7),
        "ML" => (17.6, -4.0),
        "MM" => (19.8, 96.0),
        "MN" => (46.9, 103.8),
        "MO" => (22.2, 113.5),
        "MR" => (21.0, -10.9),
        "MT" => (35.9, 14.4),
        "MU" => (-20.3, 57.6),
        "MV" => (3.2, 73.2),
        "MW" => (-13.3, 34.3),
        "MX" => (23.6, -102.6),
        "MY" => (4.2, 101.9),
        "MZ" => (-18.7, 35.5),
        "NA" => (-22.6, 17.1),
        "NE" => (17.6, 8.1),
        "NG" => (9.1, 8.7),
        "NI" => (12.9, -85.2),
        "NL" => (52.1, 5.3),
        "NO" => (60.5, 8.5),
        "NP" => (28.4, 84.1),
        "NZ" => (-41.3, 174.9),
        "OM" => (21.5, 56.0),
        "PA" => (8.5, -80.8),
        "PE" => (-9.2, -75.0),
        "PG" => (-6.3, 143.9),
        "PH" => (12.9, 121.8),
        "PK" => (30.4, 69.3),
        "PL" => (51.9, 19.1),
        "PR" => (18.2, -66.6),
        "PS" => (31.9, 35.2),
        "PT" => (39.4, -8.2),
        "PY" => (-23.4, -58.4),
        "QA" => (25.4, 51.2),
        "RO" => (45.9, 25.0),
        "RS" => (44.0, 21.0),
        "RU" => (61.5, 105.3),
        "RW" => (-2.0, 29.9),
        "SA" => (24.0, 45.0),
        "SD" => (12.9, 30.2),
        "SE" => (60.1, 18.6),
        "SG" => (1.4, 103.8),
        "SI" => (46.2, 15.0),
        "SK" => (48.7, 19.7),
        "SL" => (8.5, -11.8),
        "SN" => (14.5, -14.5),
        "SO" => (5.2, 46.2),
        "SR" => (4.0, -56.0),
        "SS" => (6.9, 31.3),
        "SV" => (13.7, -88.9),
        "SY" => (34.8, 39.0),
        "SZ" => (-26.5, 31.5),
        "TD" => (15.5, 19.0),
        "TG" => (8.6, 1.2),
        "TH" => (15.9, 100.9),
        "TJ" => (38.9, 71.3),
        "TL" => (-8.9, 126.0),
        "TM" => (39.0, 59.6),
        "TN" => (34.0, 9.5),
        "TR" => (39.0, 35.2),
        "TT" => (10.4, -61.2),
        "TW" => (23.7, 121.0),
        "TZ" => (-6.4, 34.9),
        "UA" => (48.4, 31.2),
        "UG" => (1.4, 32.3),
        "US" => (37.1, -95.7),
        "UY" => (-32.5, -55.8),
        "UZ" => (41.4, 64.6),
        "VE" => (6.4, -66.6),
        "VN" => (14.1, 108.3),
        "YE" => (15.6, 48.5),
        "ZA" => (-30.6, 22.9),
        "ZM" => (-13.1, 27.8),
        "ZW" => (-20.0, 30.0),
        _ => return None,
    })
}

// ─── Country name lookup ───────────────────────────────────────────
//
// Maps ISO 3166-1 alpha-2 codes to English country names.

pub fn country_name(code: &str) -> &'static str {
    match code {
        "AD" => "Andorra",
        "AE" => "United Arab Emirates",
        "AF" => "Afghanistan",
        "AG" => "Antigua and Barbuda",
        "AL" => "Albania",
        "AM" => "Armenia",
        "AO" => "Angola",
        "AR" => "Argentina",
        "AT" => "Austria",
        "AU" => "Australia",
        "AZ" => "Azerbaijan",
        "BA" => "Bosnia and Herzegovina",
        "BB" => "Barbados",
        "BD" => "Bangladesh",
        "BE" => "Belgium",
        "BF" => "Burkina Faso",
        "BG" => "Bulgaria",
        "BH" => "Bahrain",
        "BI" => "Burundi",
        "BJ" => "Benin",
        "BN" => "Brunei",
        "BO" => "Bolivia",
        "BR" => "Brazil",
        "BS" => "Bahamas",
        "BT" => "Bhutan",
        "BW" => "Botswana",
        "BY" => "Belarus",
        "BZ" => "Belize",
        "CA" => "Canada",
        "CD" => "DR Congo",
        "CF" => "Central African Republic",
        "CG" => "Congo",
        "CH" => "Switzerland",
        "CI" => "Ivory Coast",
        "CL" => "Chile",
        "CM" => "Cameroon",
        "CN" => "China",
        "CO" => "Colombia",
        "CR" => "Costa Rica",
        "CU" => "Cuba",
        "CY" => "Cyprus",
        "CZ" => "Czechia",
        "DE" => "Germany",
        "DJ" => "Djibouti",
        "DK" => "Denmark",
        "DO" => "Dominican Republic",
        "DZ" => "Algeria",
        "EC" => "Ecuador",
        "EE" => "Estonia",
        "EG" => "Egypt",
        "ER" => "Eritrea",
        "ES" => "Spain",
        "ET" => "Ethiopia",
        "FI" => "Finland",
        "FJ" => "Fiji",
        "FR" => "France",
        "GA" => "Gabon",
        "GB" => "United Kingdom",
        "GE" => "Georgia",
        "GH" => "Ghana",
        "GM" => "Gambia",
        "GN" => "Guinea",
        "GQ" => "Equatorial Guinea",
        "GR" => "Greece",
        "GT" => "Guatemala",
        "GW" => "Guinea-Bissau",
        "GY" => "Guyana",
        "HK" => "Hong Kong",
        "HN" => "Honduras",
        "HR" => "Croatia",
        "HT" => "Haiti",
        "HU" => "Hungary",
        "ID" => "Indonesia",
        "IE" => "Ireland",
        "IL" => "Israel",
        "IN" => "India",
        "IQ" => "Iraq",
        "IR" => "Iran",
        "IS" => "Iceland",
        "IT" => "Italy",
        "JM" => "Jamaica",
        "JO" => "Jordan",
        "JP" => "Japan",
        "KE" => "Kenya",
        "KG" => "Kyrgyzstan",
        "KH" => "Cambodia",
        "KP" => "North Korea",
        "KR" => "South Korea",
        "KW" => "Kuwait",
        "KZ" => "Kazakhstan",
        "LA" => "Laos",
        "LB" => "Lebanon",
        "LK" => "Sri Lanka",
        "LR" => "Liberia",
        "LS" => "Lesotho",
        "LT" => "Lithuania",
        "LU" => "Luxembourg",
        "LV" => "Latvia",
        "LY" => "Libya",
        "MA" => "Morocco",
        "MD" => "Moldova",
        "ME" => "Montenegro",
        "MG" => "Madagascar",
        "MK" => "North Macedonia",
        "ML" => "Mali",
        "MM" => "Myanmar",
        "MN" => "Mongolia",
        "MO" => "Macau",
        "MR" => "Mauritania",
        "MT" => "Malta",
        "MU" => "Mauritius",
        "MV" => "Maldives",
        "MW" => "Malawi",
        "MX" => "Mexico",
        "MY" => "Malaysia",
        "MZ" => "Mozambique",
        "NA" => "Namibia",
        "NE" => "Niger",
        "NG" => "Nigeria",
        "NI" => "Nicaragua",
        "NL" => "Netherlands",
        "NO" => "Norway",
        "NP" => "Nepal",
        "NZ" => "New Zealand",
        "OM" => "Oman",
        "PA" => "Panama",
        "PE" => "Peru",
        "PG" => "Papua New Guinea",
        "PH" => "Philippines",
        "PK" => "Pakistan",
        "PL" => "Poland",
        "PR" => "Puerto Rico",
        "PS" => "Palestine",
        "PT" => "Portugal",
        "PY" => "Paraguay",
        "QA" => "Qatar",
        "RO" => "Romania",
        "RS" => "Serbia",
        "RU" => "Russia",
        "RW" => "Rwanda",
        "SA" => "Saudi Arabia",
        "SD" => "Sudan",
        "SE" => "Sweden",
        "SG" => "Singapore",
        "SI" => "Slovenia",
        "SK" => "Slovakia",
        "SL" => "Sierra Leone",
        "SN" => "Senegal",
        "SO" => "Somalia",
        "SR" => "Suriname",
        "SS" => "South Sudan",
        "SV" => "El Salvador",
        "SY" => "Syria",
        "SZ" => "Eswatini",
        "TD" => "Chad",
        "TG" => "Togo",
        "TH" => "Thailand",
        "TJ" => "Tajikistan",
        "TL" => "Timor-Leste",
        "TM" => "Turkmenistan",
        "TN" => "Tunisia",
        "TR" => "Turkey",
        "TT" => "Trinidad and Tobago",
        "TW" => "Taiwan",
        "TZ" => "Tanzania",
        "UA" => "Ukraine",
        "UG" => "Uganda",
        "US" => "United States",
        "UY" => "Uruguay",
        "UZ" => "Uzbekistan",
        "VE" => "Venezuela",
        "VN" => "Vietnam",
        "YE" => "Yemen",
        "ZA" => "South Africa",
        "ZM" => "Zambia",
        "ZW" => "Zimbabwe",
        _ => "Unknown",
    }
}

// ─── Private IP detection ──────────────────────────────────────────

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

// ─── Tests ─────────────────────────────────────────────────────────

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
    fn test_lookup_google_dns() {
        let result = lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(result.is_some());
        let geo = result.unwrap();
        assert_eq!(geo.country_code, "US");
        assert!(!geo.country_name.is_empty());
    }

    #[test]
    fn test_lookup_vietnamese_ip() {
        // 14.224.x.x is a Vietnamese IP range (VNPT)
        let result = lookup(IpAddr::V4(Ipv4Addr::new(14, 224, 0, 1)));
        assert!(result.is_some());
        let geo = result.unwrap();
        assert_eq!(geo.country_code, "VN");
    }

    #[test]
    fn test_country_name_helper() {
        assert_eq!(country_name("US"), "United States");
        assert_eq!(country_name("VN"), "Vietnam");
        assert_eq!(country_name("CN"), "China");
        assert_eq!(country_name("JP"), "Japan");
        assert_eq!(country_name("XX"), "Unknown");
    }
}
