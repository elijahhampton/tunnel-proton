use std::net::{IpAddr, Ipv4Addr};

use vpnui_proto::{Feature, IpInfo, Server, ServerId};

use crate::rng::Rng;

struct City {
    name: &'static str,
    code: &'static str,
    lat: f64,
    lon: f64,
}

struct Country {
    code: &'static str,
    name: &'static str,
    cities: &'static [City],
}

const fn city(name: &'static str, code: &'static str, lat: f64, lon: f64) -> City {
    City {
        name,
        code,
        lat,
        lon,
    }
}

#[rustfmt::skip]
const COUNTRIES: &[Country] = &[
    Country { code: "US", name: "United States", cities: &[
        city("New York", "nyc", 40.7128, -74.0060),
        city("Los Angeles", "lax", 34.0522, -118.2437),
        city("Chicago", "chi", 41.8781, -87.6298),
        city("Dallas", "dal", 32.7767, -96.7970),
    ]},
    Country { code: "CA", name: "Canada", cities: &[
        city("Toronto", "tor", 43.6532, -79.3832),
        city("Montréal", "mtl", 45.5017, -73.5673),
        city("Vancouver", "van", 49.2827, -123.1207),
    ]},
    Country { code: "MX", name: "Mexico", cities: &[city("Mexico City", "mex", 19.4326, -99.1332)] },
    Country { code: "BR", name: "Brazil", cities: &[city("São Paulo", "sao", -23.5505, -46.6333)] },
    Country { code: "AR", name: "Argentina", cities: &[city("Buenos Aires", "bue", -34.6037, -58.3816)] },
    Country { code: "GB", name: "United Kingdom", cities: &[
        city("London", "lon", 51.5074, -0.1278),
        city("Manchester", "man", 53.4808, -2.2426),
    ]},
    Country { code: "IE", name: "Ireland", cities: &[city("Dublin", "dub", 53.3498, -6.2603)] },
    Country { code: "FR", name: "France", cities: &[
        city("Paris", "par", 48.8566, 2.3522),
        city("Marseille", "mrs", 43.2965, 5.3698),
    ]},
    Country { code: "DE", name: "Germany", cities: &[
        city("Frankfurt", "fra", 50.1109, 8.6821),
        city("Berlin", "ber", 52.5200, 13.4050),
        city("Munich", "muc", 48.1351, 11.5820),
    ]},
    Country { code: "NL", name: "Netherlands", cities: &[city("Amsterdam", "ams", 52.3676, 4.9041)] },
    Country { code: "CH", name: "Switzerland", cities: &[
        city("Zürich", "zrh", 47.3769, 8.5417),
        city("Geneva", "gva", 46.2044, 6.1432),
    ]},
    Country { code: "SE", name: "Sweden", cities: &[
        city("Stockholm", "sto", 59.3293, 18.0686),
        city("Gothenburg", "got", 57.7089, 11.9746),
    ]},
    Country { code: "NO", name: "Norway", cities: &[city("Oslo", "osl", 59.9139, 10.7522)] },
    Country { code: "ES", name: "Spain", cities: &[
        city("Madrid", "mad", 40.4168, -3.7038),
        city("Barcelona", "bcn", 41.3874, 2.1686),
    ]},
    Country { code: "IT", name: "Italy", cities: &[
        city("Milan", "mil", 45.4642, 9.1900),
        city("Rome", "rom", 41.9028, 12.4964),
    ]},
    Country { code: "PL", name: "Poland", cities: &[city("Warsaw", "waw", 52.2297, 21.0122)] },
    Country { code: "AT", name: "Austria", cities: &[city("Vienna", "vie", 48.2082, 16.3738)] },
    Country { code: "JP", name: "Japan", cities: &[
        city("Tokyo", "tyo", 35.6762, 139.6503),
        city("Osaka", "osa", 34.6937, 135.5023),
    ]},
    Country { code: "SG", name: "Singapore", cities: &[city("Singapore", "sin", 1.3521, 103.8198)] },
    Country { code: "AU", name: "Australia", cities: &[
        city("Sydney", "syd", -33.8688, 151.2093),
        city("Melbourne", "mel", -37.8136, 144.9631),
        city("Brisbane", "bne", -27.4698, 153.0251),
        city("Perth", "per", -31.9505, 115.8605),
    ]},
    Country { code: "IN", name: "India", cities: &[city("Mumbai", "bom", 19.0760, 72.8777)] },
    Country { code: "ZA", name: "South Africa", cities: &[city("Johannesburg", "jnb", -26.2041, 28.0473)] },
    Country { code: "KR", name: "South Korea", cities: &[city("Seoul", "sel", 37.5665, 126.9780)] },
    Country { code: "HK", name: "Hong Kong", cities: &[city("Hong Kong", "hkg", 22.3193, 114.1694)] },
];

const HOME_CITY: &str = "New York";
const HOME_COUNTRY: &str = "United States";
const HOME_LAT: f64 = 40.7128;
const HOME_LON: f64 = -74.0060;

pub(crate) const LATENCY_JITTER_MS: u64 = 9;

/// 198.51.100.0/24 (RFC 5737 TEST-NET-2) has 254 usable host addresses.
const MAX_SERVERS: usize = 254;

#[derive(Debug, Clone)]
pub(crate) struct CatalogEntry {
    pub(crate) server: Server,
    pub(crate) exit_ip: Ipv4Addr,
    pub(crate) base_latency_ms: u32,
    lat: f64,
    lon: f64,
}

impl CatalogEntry {
    pub(crate) fn exit_info(&self) -> IpInfo {
        IpInfo {
            ip: IpAddr::V4(self.exit_ip),
            city: self.server.city.clone(),
            country: self.server.country.clone(),
            lat: Some(self.lat),
            lon: Some(self.lon),
        }
    }
}

/// The user's pre-tunnel address, in RFC 5737 TEST-NET-3 (203.0.113.0/24).
pub(crate) fn home_ip(rng: &mut Rng) -> IpInfo {
    let host = rng.range(2, 254) as u8;
    IpInfo {
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, host)),
        city: HOME_CITY.into(),
        country: HOME_COUNTRY.into(),
        lat: Some(HOME_LAT),
        lon: Some(HOME_LON),
    }
}

pub(crate) fn generate(rng: &mut Rng) -> Vec<CatalogEntry> {
    let mut entries = Vec::new();
    for country in COUNTRIES {
        for city in country.cities {
            let count = rng.range(2, 7);
            let first_number = rng.range(1, 20);
            let base_latency = latency_from_home_ms(city.lat, city.lon);
            for n in first_number..first_number + count {
                if entries.len() >= MAX_SERVERS {
                    return entries;
                }
                let host = (entries.len() + 1) as u8;
                let server = Server {
                    id: ServerId::new(format!(
                        "{}-{}-{n:03}",
                        country.code.to_ascii_lowercase(),
                        city.code
                    )),
                    name: format!("{} #{n}", city.name),
                    country_code: country.code.into(),
                    country: country.name.into(),
                    city: city.name.into(),
                    lat: Some(city.lat),
                    lon: Some(city.lon),
                    load_pct: Some(rng.range(5, 95) as u8),
                    latency_ms: Some(base_latency + rng.range(0, LATENCY_JITTER_MS) as u32),
                    features: features(rng),
                    profile_id: None,
                    entry_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host))),
                    imported_at_ms: None,
                };
                entries.push(CatalogEntry {
                    server,
                    exit_ip: Ipv4Addr::new(198, 51, 100, host),
                    base_latency_ms: base_latency,
                    lat: city.lat,
                    lon: city.lon,
                });
            }
        }
    }
    entries
}

fn features(rng: &mut Rng) -> Vec<Feature> {
    [
        (Feature::P2p, 0.45),
        (Feature::Streaming, 0.35),
        (Feature::Multihop, 0.15),
    ]
    .into_iter()
    .filter(|&(_, p)| rng.chance(p))
    .map(|(f, _)| f)
    .collect()
}

/// Round-trip estimate: great-circle distance at roughly 80 km per millisecond of RTT,
/// which approximates fiber propagation plus routing overhead.
fn latency_from_home_ms(lat: f64, lon: f64) -> u32 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let (lat1, lon1) = (HOME_LAT.to_radians(), HOME_LON.to_radians());
    let (lat2, lon2) = (lat.to_radians(), lon.to_radians());
    let a = ((lat2 - lat1) / 2.0).sin().powi(2)
        + lat1.cos() * lat2.cos() * ((lon2 - lon1) / 2.0).sin().powi(2);
    let distance_km = 2.0 * EARTH_RADIUS_KM * a.sqrt().asin();
    4 + (distance_km / 80.0) as u32
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn catalog_is_deterministic_and_well_formed() {
        let a = generate(&mut Rng::new(1));
        let b = generate(&mut Rng::new(1));
        assert_eq!(
            a.iter().map(|e| &e.server).collect::<Vec<_>>(),
            b.iter().map(|e| &e.server).collect::<Vec<_>>()
        );

        assert!((150..=220).contains(&a.len()), "got {} servers", a.len());
        let countries: HashSet<_> = a.iter().map(|e| &e.server.country_code).collect();
        assert_eq!(countries.len(), COUNTRIES.len());

        let ids: HashSet<_> = a.iter().map(|e| &e.server.id).collect();
        assert_eq!(ids.len(), a.len(), "server ids must be unique");
        let ips: HashSet<_> = a.iter().map(|e| e.exit_ip).collect();
        assert_eq!(ips.len(), a.len(), "exit IPs must be unique");

        for entry in &a {
            let s = &entry.server;
            assert!(s.load_pct.is_some_and(|l| (5..=95).contains(&l)));
            assert!(s.latency_ms.is_some_and(|l| l >= 4));
            assert_eq!(s.entry_ip, Some(IpAddr::V4(entry.exit_ip)));
            assert_eq!(entry.exit_ip.octets()[..3], [198, 51, 100]);
        }
    }

    #[test]
    fn latency_grows_with_distance() {
        let nyc = latency_from_home_ms(40.7128, -74.0060);
        let london = latency_from_home_ms(51.5074, -0.1278);
        let sydney = latency_from_home_ms(-33.8688, 151.2093);
        assert!(nyc < london && london < sydney);
    }
}
