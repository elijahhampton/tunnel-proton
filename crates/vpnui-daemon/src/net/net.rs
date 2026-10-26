//! Validated network values. Everything that reaches a command line or a pf rule is one of
//! these types, never free text.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An interface name such as `utun4` or `en0`: lowercase letters then digits, at most 15 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IfName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid interface name")]
pub struct IfNameError;

impl IfName {
    /// For compile-time literals known to be valid.
    pub(crate) fn from_static(name: &'static str) -> Self {
        Self(name.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_tunnel(&self) -> bool {
        self.0.starts_with("utun")
    }
}

impl FromStr for IfName {
    type Err = IfNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let letters = s.bytes().take_while(u8::is_ascii_lowercase).count();
        let digits = s.len() - letters;
        let valid = (1..=15).contains(&s.len())
            && letters >= 1
            && digits >= 1
            && s.bytes().skip(letters).all(|b| b.is_ascii_digit());
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(IfNameError)
        }
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for IfName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IfName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An address with a prefix length, e.g. `10.2.0.2/32` or `::/0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpNetError {
    #[error("not an IP address")]
    Address,
    #[error("prefix length out of range")]
    Prefix,
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, IpNetError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(IpNetError::Prefix);
        }
        Ok(Self { addr, prefix })
    }

    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }
}

impl FromStr for IpNet {
    type Err = IpNetError;

    /// A bare address gets the host prefix (/32 or /128), matching wg-quick.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| IpNetError::Address)?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| IpNetError::Prefix)?,
            None => max,
        };
        Self::new(addr, prefix)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for IpNet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The routes that send everything into the tunnel without replacing the real default route.
/// Returns the four /1 subnets that effectively span the entire IPv4 and IPv6 
/// address spaces, splitting each right down the middle.
///
/// With this approach we take advantage of the Longest Prefix Match Rule.
/// Operating system routing tables always prioritize a more specific route 
/// (longer prefix) over a less specific one. The standard default route is 
/// `0.0.0.0/0` (prefix length 0). 
///
/// By injecting these `/1` routes into the routing table, we seamlessly 
/// hijack **all** internet traffic into our tunnel interface because a `/1` 
/// mask *always* overrides a `/0` mask.
///
/// With this approach We don't have to delete or alter the physical 
/// interface's original `0.0.0.0/0` default route or guess its metric.
/// 
/// When the VPN disconnects, deleting these four `/1` 
/// routes instantly and safely restores normal internet connectivity.
///
/// Covered Spaces:
/// - `0.0.0.0/1`   -> Covers `0.0.0.0` to `127.255.255.255`
/// - `128.0.0.0/1` -> Covers `128.0.0.0` to `255.255.255.255`
/// - `::/1`        -> Covers first half of IPv6 space (`0000::` to `7fff:...`)
/// - `8000::/1`    -> Covers second half of IPv6 space (`8000::` to `ffff:...`)
pub fn split_default_routes() -> [IpNet; 4] {
    let v4 = |a, p| IpNet {
        addr: IpAddr::V4(Ipv4Addr::new(a, 0, 0, 0)),
        prefix: p,
    };
    [
        v4(0, 1),
        v4(128, 1),
        IpNet {
            addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            prefix: 1,
        },
        IpNet {
            addr: IpAddr::V6(std::net::Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 1,
        },
    ]
}

/// The physical default route, as reported by `route -n get default`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultRoute {
    pub gateway: Ipv4Addr,
    pub interface: IfName,
    pub address: Option<Ipv4Addr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names() {
        for good in ["utun4", "en0", "bridge100", "utun12345"] {
            assert!(good.parse::<IfName>().is_ok(), "{good}");
        }
        for bad in [
            "", "utun", "4", "utun4;", "UTUN4", "utun 4", "en0\n", "a1b2", "../x1",
        ] {
            assert!(bad.parse::<IfName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn nets() {
        assert_eq!(
            "10.2.0.2/32".parse::<IpNet>().map(|n| n.to_string()),
            Ok("10.2.0.2/32".into())
        );
        assert_eq!("10.2.0.2".parse::<IpNet>().map(|n| n.prefix), Ok(32));
        assert_eq!("fd00::2".parse::<IpNet>().map(|n| n.prefix), Ok(128));
        assert!("0.0.0.0/0".parse::<IpNet>().is_ok_and(|n| n.is_default()));
        assert_eq!("10.0.0.0/33".parse::<IpNet>(), Err(IpNetError::Prefix));
        assert_eq!("vpn.example/24".parse::<IpNet>(), Err(IpNetError::Address));
        let rendered: Vec<String> = split_default_routes()
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(rendered, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
    }
}
