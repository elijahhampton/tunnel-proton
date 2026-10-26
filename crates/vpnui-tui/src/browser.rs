//! Server tree (country > city > server) with search and sort. Selection and expansion are keyed
//! by stable ids; rows are recomputed from the server list on demand.

use std::collections::{BTreeMap, HashSet};

use vpnui_proto::{Server, ServerId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Country(String),
    City { country: String, city: String },
    Server(ServerId),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortKey {
    #[default]
    Name,
    Load,
    Latency,
}

impl SortKey {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Load,
            Self::Load => Self::Latency,
            Self::Latency => Self::Name,
        }
    }

    /// Name always; load and latency only when some server reports them.
    pub fn available(self, servers: &[Server]) -> bool {
        match self {
            Self::Name => true,
            Self::Load => servers.iter().any(|s| s.load_pct.is_some()),
            Self::Latency => servers.iter().any(|s| s.latency_ms.is_some()),
        }
    }

    /// The next sort after `self` that the data supports.
    pub fn next_available(self, servers: &[Server]) -> Self {
        let mut next = self.next();
        while !next.available(servers) {
            next = next.next();
        }
        next
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Load => "load",
            Self::Latency => "latency",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RowKind<'a> {
    Country {
        code: &'a str,
        name: &'a str,
        servers: usize,
        avg_load: Option<u8>,
    },
    City {
        name: &'a str,
        servers: usize,
        avg_load: Option<u8>,
    },
    Server(&'a Server),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row<'a> {
    pub key: NodeKey,
    pub depth: u16,
    pub expanded: bool,
    pub kind: RowKind<'a>,
}

#[derive(Debug, Clone, Default)]
pub struct Browser {
    pub expanded: HashSet<NodeKey>,
    pub selected: Option<NodeKey>,
    pub query: String,
    /// Keystrokes go to `query` while true.
    pub typing: bool,
    pub sort: SortKey,
    pub offset: usize,
    /// Ancestors of `selected` when it was chosen, for falling back after it disappears.
    anchor: Vec<NodeKey>,
}

struct CityGroup<'a> {
    name: &'a str,
    servers: Vec<&'a Server>,
}

struct CountryGroup<'a> {
    code: &'a str,
    name: &'a str,
    cities: Vec<CityGroup<'a>>,
}

impl CountryGroup<'_> {
    fn servers(&self) -> impl Iterator<Item = &Server> {
        self.cities.iter().flat_map(|c| c.servers.iter().copied())
    }
}

/// Case-insensitive substring match over country, city, and server name.
pub fn matches(server: &Server, query_lower: &str) -> bool {
    [&server.country, &server.city, &server.name]
        .iter()
        .any(|field| field.to_lowercase().contains(query_lower))
}

/// Average over the servers that report a load; `None` when none do.
fn avg_load<'a>(servers: impl Iterator<Item = &'a Server>) -> Option<u8> {
    let (sum, n) = servers
        .filter_map(|s| s.load_pct)
        .fold((0u32, 0u32), |(sum, n), load| {
            (sum + u32::from(load), n + 1)
        });
    (n > 0).then(|| ((sum + n / 2) / n) as u8)
}

fn min_latency<'a>(servers: impl Iterator<Item = &'a Server>) -> Option<u32> {
    servers.filter_map(|s| s.latency_ms).min()
}

/// Sort key that orders known values ascending and unknown values last.
fn known_first<T: Ord>(value: Option<T>) -> (bool, Option<T>) {
    (value.is_none(), value)
}

impl Browser {
    pub fn searching(&self) -> bool {
        !self.query.trim().is_empty()
    }

    pub fn rows<'a>(&self, servers: &'a [Server]) -> Vec<Row<'a>> {
        let query = self.query.trim().to_lowercase();
        let searching = !query.is_empty();

        let mut by_country: BTreeMap<&str, (&str, BTreeMap<&str, Vec<&Server>>)> = BTreeMap::new();
        for server in servers.iter().filter(|s| !searching || matches(s, &query)) {
            by_country
                .entry(&server.country_code)
                .or_insert_with(|| (&server.country, BTreeMap::new()))
                .1
                .entry(&server.city)
                .or_default()
                .push(server);
        }

        let mut countries: Vec<CountryGroup<'a>> = by_country
            .into_iter()
            .map(|(code, (name, cities))| CountryGroup {
                code,
                name,
                cities: cities
                    .into_iter()
                    .map(|(name, servers)| CityGroup { name, servers })
                    .collect(),
            })
            .collect();
        self.sort_groups(&mut countries);

        let mut rows = Vec::new();
        for country in &countries {
            let country_key = NodeKey::Country(country.code.to_owned());
            let country_open = searching || self.expanded.contains(&country_key);
            rows.push(Row {
                key: country_key,
                depth: 0,
                expanded: country_open,
                kind: RowKind::Country {
                    code: country.code,
                    name: country.name,
                    servers: country.servers().count(),
                    avg_load: avg_load(country.servers()),
                },
            });
            if !country_open {
                continue;
            }
            for city in &country.cities {
                let city_key = NodeKey::City {
                    country: country.code.to_owned(),
                    city: city.name.to_owned(),
                };
                let city_open = searching || self.expanded.contains(&city_key);
                rows.push(Row {
                    key: city_key,
                    depth: 1,
                    expanded: city_open,
                    kind: RowKind::City {
                        name: city.name,
                        servers: city.servers.len(),
                        avg_load: avg_load(city.servers.iter().copied()),
                    },
                });
                if city_open {
                    rows.extend(city.servers.iter().map(|s| Row {
                        key: NodeKey::Server(s.id.clone()),
                        depth: 2,
                        expanded: false,
                        kind: RowKind::Server(s),
                    }));
                }
            }
        }
        rows
    }

    fn sort_groups(&self, countries: &mut [CountryGroup<'_>]) {
        for country in countries.iter_mut() {
            for city in &mut country.cities {
                match self.sort {
                    SortKey::Name => city.servers.sort_by(|a, b| a.id.cmp(&b.id)),
                    SortKey::Load => {
                        city.servers
                            .sort_by_key(|s| (known_first(s.load_pct), s.id.clone()));
                    }
                    SortKey::Latency => {
                        city.servers
                            .sort_by_key(|s| (known_first(s.latency_ms), s.id.clone()));
                    }
                }
            }
            match self.sort {
                SortKey::Name => country.cities.sort_by(|a, b| a.name.cmp(b.name)),
                SortKey::Load => country
                    .cities
                    .sort_by_key(|c| (known_first(avg_load(c.servers.iter().copied())), c.name)),
                SortKey::Latency => country
                    .cities
                    .sort_by_key(|c| (known_first(min_latency(c.servers.iter().copied())), c.name)),
            }
        }
        match self.sort {
            SortKey::Name => countries.sort_by(|a, b| a.name.cmp(b.name)),
            SortKey::Load => {
                countries.sort_by_key(|c| (known_first(avg_load(c.servers())), c.name));
            }
            SortKey::Latency => {
                countries.sort_by_key(|c| (known_first(min_latency(c.servers())), c.name));
            }
        }
    }

    pub fn selected_index(&self, rows: &[Row<'_>]) -> Option<usize> {
        let selected = self.selected.as_ref()?;
        rows.iter().position(|r| r.key == *selected)
    }

    pub fn select(&mut self, key: NodeKey, servers: &[Server]) {
        self.anchor = ancestors(&key, servers);
        self.selected = Some(key);
    }

    pub fn selected_server<'a>(&self, servers: &'a [Server]) -> Option<&'a Server> {
        match self.selected.as_ref()? {
            NodeKey::Server(id) => servers.iter().find(|s| s.id == *id),
            NodeKey::Country(_) | NodeKey::City { .. } => None,
        }
    }

    /// Keeps the selection on a visible row: the same key if it is still shown, else its nearest
    /// visible ancestor, else the first row.
    pub fn reconcile(&mut self, servers: &[Server]) {
        if !servers.is_empty() && !self.sort.available(servers) {
            self.sort = SortKey::Name;
        }
        let rows = self.rows(servers);
        if self.selected_index(&rows).is_some() {
            return;
        }
        let candidates = match &self.selected {
            Some(key) => {
                let fresh = ancestors(key, servers);
                if fresh.is_empty() {
                    std::mem::take(&mut self.anchor)
                } else {
                    fresh
                }
            }
            None => Vec::new(),
        };
        let fallback = candidates
            .into_iter()
            .find(|key| rows.iter().any(|r| r.key == *key))
            .or_else(|| rows.first().map(|r| r.key.clone()));
        match fallback {
            Some(key) => self.select(key, servers),
            None => self.selected = None,
        }
    }

    pub fn move_by(&mut self, servers: &[Server], delta: isize) {
        self.reconcile(servers);
        let rows = self.rows(servers);
        if rows.is_empty() {
            return;
        }
        let current = self.selected_index(&rows).unwrap_or(0);
        let next = current.saturating_add_signed(delta).min(rows.len() - 1);
        self.select(rows[next].key.clone(), servers);
    }

    pub fn select_index(&mut self, servers: &[Server], index: usize) {
        if let Some(row) = self.rows(servers).get(index) {
            self.select(row.key.clone(), servers);
        }
    }

    pub fn toggle(&mut self, key: &NodeKey) {
        if !self.expanded.remove(key) {
            self.expanded.insert(key.clone());
        }
    }

    /// Collapses the selected group, or moves to the parent of a leaf or collapsed group.
    pub fn collapse(&mut self, servers: &[Server]) {
        self.reconcile(servers);
        let Some(key) = self.selected.clone() else {
            return;
        };
        let is_open = self
            .rows(servers)
            .iter()
            .any(|r| r.key == key && r.expanded && !matches!(r.key, NodeKey::Server(_)));
        if is_open && !self.searching() {
            self.expanded.remove(&key);
        } else if let Some(parent) = ancestors(&key, servers).into_iter().next() {
            self.select(parent, servers);
        }
    }

    /// Expands the selected group, or moves to its first child when already open.
    pub fn expand(&mut self, servers: &[Server]) {
        self.reconcile(servers);
        let Some(key) = self.selected.clone() else {
            return;
        };
        match &key {
            NodeKey::Server(_) => {}
            NodeKey::Country(_) | NodeKey::City { .. } => {
                let rows = self.rows(servers);
                let open = rows.iter().any(|r| r.key == key && r.expanded);
                if open {
                    self.move_by(servers, 1);
                } else {
                    self.expanded.insert(key);
                }
            }
        }
    }

    /// Scrolls the minimum amount needed to keep the selection inside a `viewport`-row window.
    pub fn clamp_offset(&mut self, servers: &[Server], viewport: usize) {
        let rows = self.rows(servers);
        self.offset = clamp_scroll(
            self.offset,
            self.selected_index(&rows),
            viewport,
            rows.len(),
        );
    }
}

/// Parent first, then grandparent.
fn ancestors(key: &NodeKey, servers: &[Server]) -> Vec<NodeKey> {
    match key {
        NodeKey::Country(_) => Vec::new(),
        NodeKey::City { country, .. } => vec![NodeKey::Country(country.clone())],
        NodeKey::Server(id) => servers
            .iter()
            .find(|s| s.id == *id)
            .map(|s| {
                vec![
                    NodeKey::City {
                        country: s.country_code.clone(),
                        city: s.city.clone(),
                    },
                    NodeKey::Country(s.country_code.clone()),
                ]
            })
            .unwrap_or_default(),
    }
}

pub fn clamp_scroll(
    offset: usize,
    selected: Option<usize>,
    viewport: usize,
    total: usize,
) -> usize {
    if viewport == 0 {
        return 0;
    }
    let mut offset = offset.min(total.saturating_sub(viewport));
    if let Some(selected) = selected {
        if selected < offset {
            offset = selected;
        } else if selected >= offset + viewport {
            offset = selected + 1 - viewport;
        }
    }
    offset
}

#[cfg(test)]
mod tests {
    use vpnui_proto::Feature;

    use super::*;

    fn server(id: &str, cc: &str, country: &str, city: &str, load: u8, latency: u32) -> Server {
        Server {
            id: ServerId::new(id),
            name: format!("{city} #{}", &id[id.len() - 2..]),
            country_code: cc.into(),
            country: country.into(),
            city: city.into(),
            lat: Some(0.0),
            lon: Some(0.0),
            load_pct: Some(load),
            latency_ms: Some(latency),
            features: vec![Feature::P2p],
            profile_id: None,
            entry_ip: None,
            imported_at_ms: None,
        }
    }

    fn profile(id: &str, cc: &str, country: &str) -> Server {
        Server {
            load_pct: None,
            latency_ms: None,
            city: String::new(),
            ..server(id, cc, country, "", 0, 0)
        }
    }

    fn fleet() -> Vec<Server> {
        vec![
            server("ch-zrh-012", "CH", "Switzerland", "Zürich", 41, 92),
            server("ch-zrh-003", "CH", "Switzerland", "Zürich", 70, 95),
            server("ch-gva-001", "CH", "Switzerland", "Geneva", 20, 99),
            server("se-sto-002", "SE", "Sweden", "Stockholm", 10, 110),
            server("jp-tyo-007", "JP", "Japan", "Tokyo", 88, 180),
        ]
    }

    fn keys(rows: &[Row<'_>]) -> Vec<String> {
        rows.iter()
            .map(|r| match &r.key {
                NodeKey::Country(cc) => cc.clone(),
                NodeKey::City { city, .. } => format!("  {city}"),
                NodeKey::Server(id) => format!("    {id}"),
            })
            .collect()
    }

    #[test]
    fn collapsed_tree_lists_countries_by_name() {
        let servers = fleet();
        let browser = Browser::default();
        assert_eq!(keys(&browser.rows(&servers)), ["JP", "SE", "CH"]);
    }

    #[test]
    fn country_rows_aggregate_counts_and_load() {
        let servers = fleet();
        let rows = Browser::default().rows(&servers);
        let ch = rows.iter().find(|r| r.key == NodeKey::Country("CH".into()));
        assert_eq!(
            ch.map(|r| &r.kind),
            Some(&RowKind::Country {
                code: "CH",
                name: "Switzerland",
                servers: 3,
                avg_load: Some(44)
            })
        );
    }

    #[test]
    fn search_is_case_insensitive_over_country_city_and_name() {
        let servers = fleet();
        let mut browser = Browser {
            query: "zürICH".into(),
            ..Browser::default()
        };
        assert_eq!(
            keys(&browser.rows(&servers)),
            ["CH", "  Zürich", "    ch-zrh-003", "    ch-zrh-012"]
        );

        browser.query = "swed".into();
        assert_eq!(
            keys(&browser.rows(&servers)),
            ["SE", "  Stockholm", "    se-sto-002"]
        );

        browser.query = "#07".into();
        assert_eq!(
            keys(&browser.rows(&servers)),
            ["JP", "  Tokyo", "    jp-tyo-007"]
        );

        browser.query = "atlantis".into();
        assert!(browser.rows(&servers).is_empty());
    }

    #[test]
    fn sort_orders_every_level() {
        let servers = fleet();
        let mut browser = Browser {
            sort: SortKey::Load,
            ..Browser::default()
        };
        for s in &servers {
            browser
                .expanded
                .insert(NodeKey::Country(s.country_code.clone()));
            browser.expanded.insert(NodeKey::City {
                country: s.country_code.clone(),
                city: s.city.clone(),
            });
        }
        assert_eq!(
            keys(&browser.rows(&servers)),
            [
                "SE",
                "  Stockholm",
                "    se-sto-002",
                "CH",
                "  Geneva",
                "    ch-gva-001",
                "  Zürich",
                "    ch-zrh-012",
                "    ch-zrh-003",
                "JP",
                "  Tokyo",
                "    jp-tyo-007",
            ]
        );

        browser.sort = SortKey::Latency;
        let rows = browser.rows(&servers);
        assert_eq!(keys(&rows)[0], "CH");
        assert_eq!(keys(&rows)[1], "  Zürich");
        assert_eq!(keys(&rows)[2], "    ch-zrh-012");

        assert_eq!(SortKey::Name.next().next().next(), SortKey::Name);
    }

    #[test]
    fn selection_survives_reorder_and_reload() {
        let mut servers = fleet();
        let mut browser = Browser {
            sort: SortKey::Load,
            ..Browser::default()
        };
        browser.expanded.insert(NodeKey::Country("CH".into()));
        browser.expanded.insert(NodeKey::City {
            country: "CH".into(),
            city: "Zürich".into(),
        });
        let target = NodeKey::Server(ServerId::new("ch-zrh-003"));
        browser.select(target.clone(), &servers);
        let before = browser.selected_index(&browser.rows(&servers));

        // servers_updated: loads shift enough to reorder the Zürich servers, and the list is
        // replaced wholesale with fresh values.
        servers[0].load_pct = Some(90);
        servers[1].load_pct = Some(5);
        let servers: Vec<Server> = servers.iter().rev().cloned().collect();
        browser.reconcile(&servers);

        assert_eq!(browser.selected, Some(target));
        assert_ne!(browser.selected_index(&browser.rows(&servers)), before);
    }

    #[test]
    fn removed_server_falls_back_to_its_city() {
        let servers = fleet();
        let mut browser = Browser::default();
        browser.expanded.insert(NodeKey::Country("CH".into()));
        browser.expanded.insert(NodeKey::City {
            country: "CH".into(),
            city: "Zürich".into(),
        });
        browser.select(NodeKey::Server(ServerId::new("ch-zrh-003")), &servers);

        let mut fewer = servers.clone();
        fewer.retain(|s| s.id.as_str() != "ch-zrh-003");
        browser.reconcile(&fewer);
        assert_eq!(
            browser.selected,
            Some(NodeKey::City {
                country: "CH".into(),
                city: "Zürich".into()
            })
        );

        browser.expanded.clear();
        browser.reconcile(&fewer);
        assert_eq!(browser.selected, Some(NodeKey::Country("CH".into())));
    }

    #[test]
    fn expand_collapse_navigation() {
        let servers = fleet();
        let mut browser = Browser::default();
        browser.reconcile(&servers);
        assert_eq!(browser.selected, Some(NodeKey::Country("JP".into())));

        browser.move_by(&servers, 2);
        assert_eq!(browser.selected, Some(NodeKey::Country("CH".into())));
        browser.expand(&servers);
        assert!(browser.expanded.contains(&NodeKey::Country("CH".into())));
        browser.expand(&servers);
        assert_eq!(
            browser.selected,
            Some(NodeKey::City {
                country: "CH".into(),
                city: "Geneva".into()
            })
        );
        browser.collapse(&servers);
        assert_eq!(browser.selected, Some(NodeKey::Country("CH".into())));
        browser.collapse(&servers);
        assert!(!browser.expanded.contains(&NodeKey::Country("CH".into())));

        browser.move_by(&servers, 99);
        assert_eq!(browser.selected, Some(NodeKey::Country("CH".into())));
        browser.move_by(&servers, -99);
        assert_eq!(browser.selected, Some(NodeKey::Country("JP".into())));
    }

    #[test]
    fn unknown_loads_are_excluded_from_averages_and_sort_last() {
        let mut servers = fleet();
        servers.push(profile("ch-x-099", "CH", "Switzerland"));
        servers.push(profile("co-4-aaaaaa", "CO", "Colombia"));
        let mut browser = Browser {
            sort: SortKey::Load,
            ..Browser::default()
        };
        let rows = browser.rows(&servers);
        assert_eq!(keys(&rows).last().map(String::as_str), Some("CO"));
        let co = rows.iter().find(|r| r.key == NodeKey::Country("CO".into()));
        assert!(matches!(
            co.map(|r| &r.kind),
            Some(RowKind::Country { avg_load: None, .. })
        ));
        let ch = rows.iter().find(|r| r.key == NodeKey::Country("CH".into()));
        assert!(matches!(
            ch.map(|r| &r.kind),
            Some(RowKind::Country {
                servers: 4,
                avg_load: Some(44),
                ..
            })
        ));

        browser.sort = SortKey::Latency;
        assert_eq!(
            keys(&browser.rows(&servers)).last().map(String::as_str),
            Some("CO")
        );
    }

    #[test]
    fn sort_options_adapt_to_available_data() {
        let profiles = vec![
            profile("co-4-aaaaaa", "CO", "Colombia"),
            profile("co-7-bbbbbb", "CO", "Colombia"),
        ];
        assert!(SortKey::Name.available(&profiles));
        assert!(!SortKey::Load.available(&profiles));
        assert!(!SortKey::Latency.available(&profiles));
        assert_eq!(SortKey::Name.next_available(&profiles), SortKey::Name);

        let fleet = fleet();
        assert_eq!(SortKey::Name.next_available(&fleet), SortKey::Load);
        assert_eq!(SortKey::Latency.next_available(&fleet), SortKey::Name);

        let mut browser = Browser {
            sort: SortKey::Latency,
            ..Browser::default()
        };
        browser.reconcile(&profiles);
        assert_eq!(
            browser.sort,
            SortKey::Name,
            "unavailable sort falls back to name"
        );
        browser.sort = SortKey::Load;
        browser.reconcile(&[]);
        assert_eq!(
            browser.sort,
            SortKey::Load,
            "an empty list does not reset the choice"
        );
    }

    #[test]
    fn empty_city_still_forms_a_group() {
        let profiles = vec![
            profile("co-4-aaaaaa", "CO", "Colombia"),
            profile("co-7-bbbbbb", "CO", "Colombia"),
        ];
        let browser = Browser {
            query: "colombia".into(),
            ..Browser::default()
        };
        assert_eq!(
            keys(&browser.rows(&profiles)),
            ["CO", "  ", "    co-4-aaaaaa", "    co-7-bbbbbb"]
        );
    }

    #[test]
    fn scroll_follows_selection_minimally() {
        assert_eq!(clamp_scroll(0, Some(3), 5, 20), 0);
        assert_eq!(clamp_scroll(0, Some(5), 5, 20), 1);
        assert_eq!(clamp_scroll(10, Some(4), 5, 20), 4);
        assert_eq!(clamp_scroll(18, Some(19), 5, 20), 15);
        assert_eq!(clamp_scroll(7, None, 5, 6), 1);
        assert_eq!(clamp_scroll(7, Some(2), 0, 6), 0);
    }
}
