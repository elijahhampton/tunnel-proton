//! ISO 3166-1 alpha-2 codes with a display name and a rough centroid for the map.

pub struct Country {
    pub code: &'static str,
    pub name: &'static str,
    pub lat: f64,
    pub lon: f64,
}

const fn c(code: &'static str, name: &'static str, lat: f64, lon: f64) -> Country {
    Country {
        code,
        name,
        lat,
        lon,
    }
}

/// ISO 3166-1 exceptional reservations that providers use in server names.
const ALIASES: &[(&str, &str)] = &[("UK", "GB"), ("EL", "GR")];

pub fn lookup(code: &str) -> Option<&'static Country> {
    let upper = code.to_ascii_uppercase();
    let canonical = ALIASES
        .iter()
        .find(|(alias, _)| *alias == upper)
        .map_or(upper.as_str(), |(_, real)| real);
    COUNTRIES.iter().find(|c| c.code == canonical)
}

/// The canonical code for `code` if it is known, e.g. `uk` becomes `GB`.
pub fn canonical(code: &str) -> Option<&'static str> {
    lookup(code).map(|c| c.code)
}

#[rustfmt::skip]
pub const COUNTRIES: &[Country] = &[
    c("AD", "Andorra", 42.55, 1.60), c("AE", "United Arab Emirates", 23.42, 53.85),
    c("AF", "Afghanistan", 33.94, 67.71), c("AG", "Antigua and Barbuda", 17.06, -61.80),
    c("AI", "Anguilla", 18.22, -63.07), c("AL", "Albania", 41.15, 20.17),
    c("AM", "Armenia", 40.07, 45.04), c("AO", "Angola", -11.20, 17.87),
    c("AQ", "Antarctica", -75.25, -0.07), c("AR", "Argentina", -38.42, -63.62),
    c("AS", "American Samoa", -14.27, -170.13), c("AT", "Austria", 47.52, 14.55),
    c("AU", "Australia", -25.27, 133.78), c("AW", "Aruba", 12.52, -69.97),
    c("AX", "Åland Islands", 60.18, 19.92), c("AZ", "Azerbaijan", 40.14, 47.58),
    c("BA", "Bosnia and Herzegovina", 43.92, 17.68), c("BB", "Barbados", 13.19, -59.54),
    c("BD", "Bangladesh", 23.68, 90.36), c("BE", "Belgium", 50.50, 4.47),
    c("BF", "Burkina Faso", 12.24, -1.56), c("BG", "Bulgaria", 42.73, 25.49),
    c("BH", "Bahrain", 25.93, 50.64), c("BI", "Burundi", -3.37, 29.92),
    c("BJ", "Benin", 9.31, 2.32), c("BL", "Saint Barthélemy", 17.90, -62.83),
    c("BM", "Bermuda", 32.32, -64.76), c("BN", "Brunei", 4.54, 114.73),
    c("BO", "Bolivia", -16.29, -63.59), c("BQ", "Caribbean Netherlands", 12.18, -68.24),
    c("BR", "Brazil", -14.24, -51.93), c("BS", "Bahamas", 25.03, -77.40),
    c("BT", "Bhutan", 27.51, 90.43), c("BV", "Bouvet Island", -54.42, 3.41),
    c("BW", "Botswana", -22.33, 24.68), c("BY", "Belarus", 53.71, 27.95),
    c("BZ", "Belize", 17.19, -88.50), c("CA", "Canada", 56.13, -106.35),
    c("CC", "Cocos (Keeling) Islands", -12.16, 96.87), c("CD", "DR Congo", -4.04, 21.76),
    c("CF", "Central African Republic", 6.61, 20.94), c("CG", "Congo", -0.23, 15.83),
    c("CH", "Switzerland", 46.82, 8.23), c("CI", "Côte d'Ivoire", 7.54, -5.55),
    c("CK", "Cook Islands", -21.24, -159.78), c("CL", "Chile", -35.68, -71.54),
    c("CM", "Cameroon", 7.37, 12.35), c("CN", "China", 35.86, 104.20),
    c("CO", "Colombia", 4.57, -74.30), c("CR", "Costa Rica", 9.75, -83.75),
    c("CU", "Cuba", 21.52, -77.78), c("CV", "Cabo Verde", 16.00, -24.01),
    c("CW", "Curaçao", 12.17, -68.99), c("CX", "Christmas Island", -10.45, 105.69),
    c("CY", "Cyprus", 35.13, 33.43), c("CZ", "Czechia", 49.82, 15.47),
    c("DE", "Germany", 51.17, 10.45), c("DJ", "Djibouti", 11.83, 42.59),
    c("DK", "Denmark", 56.26, 9.50), c("DM", "Dominica", 15.41, -61.37),
    c("DO", "Dominican Republic", 18.74, -70.16), c("DZ", "Algeria", 28.03, 1.66),
    c("EC", "Ecuador", -1.83, -78.18), c("EE", "Estonia", 58.60, 25.01),
    c("EG", "Egypt", 26.82, 30.80), c("EH", "Western Sahara", 24.22, -12.89),
    c("ER", "Eritrea", 15.18, 39.78), c("ES", "Spain", 40.46, -3.75),
    c("ET", "Ethiopia", 9.15, 40.49), c("FI", "Finland", 61.92, 25.75),
    c("FJ", "Fiji", -16.58, 179.41), c("FK", "Falkland Islands", -51.80, -59.52),
    c("FM", "Micronesia", 7.43, 150.55), c("FO", "Faroe Islands", 61.89, -6.91),
    c("FR", "France", 46.23, 2.21), c("GA", "Gabon", -0.80, 11.61),
    c("GB", "United Kingdom", 55.38, -3.44), c("GD", "Grenada", 12.26, -61.60),
    c("GE", "Georgia", 42.32, 43.36), c("GF", "French Guiana", 3.93, -53.13),
    c("GG", "Guernsey", 49.47, -2.59), c("GH", "Ghana", 7.95, -1.02),
    c("GI", "Gibraltar", 36.14, -5.35), c("GL", "Greenland", 71.71, -42.60),
    c("GM", "Gambia", 13.44, -15.31), c("GN", "Guinea", 9.95, -9.70),
    c("GP", "Guadeloupe", 17.00, -62.07), c("GQ", "Equatorial Guinea", 1.65, 10.27),
    c("GR", "Greece", 39.07, 21.82), c("GS", "South Georgia and the South Sandwich Islands", -54.43, -36.59),
    c("GT", "Guatemala", 15.78, -90.23), c("GU", "Guam", 13.44, 144.79),
    c("GW", "Guinea-Bissau", 11.80, -15.18), c("GY", "Guyana", 4.86, -58.93),
    c("HK", "Hong Kong", 22.40, 114.11), c("HM", "Heard Island and McDonald Islands", -53.08, 73.50),
    c("HN", "Honduras", 15.20, -86.24), c("HR", "Croatia", 45.10, 15.20),
    c("HT", "Haiti", 18.97, -72.29), c("HU", "Hungary", 47.16, 19.50),
    c("ID", "Indonesia", -0.79, 113.92), c("IE", "Ireland", 53.41, -8.24),
    c("IL", "Israel", 31.05, 34.85), c("IM", "Isle of Man", 54.24, -4.55),
    c("IN", "India", 20.59, 78.96), c("IO", "British Indian Ocean Territory", -6.34, 71.88),
    c("IQ", "Iraq", 33.22, 43.68), c("IR", "Iran", 32.43, 53.69),
    c("IS", "Iceland", 64.96, -19.02), c("IT", "Italy", 41.87, 12.57),
    c("JE", "Jersey", 49.21, -2.13), c("JM", "Jamaica", 18.11, -77.30),
    c("JO", "Jordan", 30.59, 36.24), c("JP", "Japan", 36.20, 138.25),
    c("KE", "Kenya", -0.02, 37.91), c("KG", "Kyrgyzstan", 41.20, 74.77),
    c("KH", "Cambodia", 12.57, 104.99), c("KI", "Kiribati", -3.37, -168.73),
    c("KM", "Comoros", -11.88, 43.87), c("KN", "Saint Kitts and Nevis", 17.36, -62.78),
    c("KP", "North Korea", 40.34, 127.51), c("KR", "South Korea", 35.91, 127.77),
    c("KW", "Kuwait", 29.31, 47.48), c("KY", "Cayman Islands", 19.51, -80.57),
    c("KZ", "Kazakhstan", 48.02, 66.92), c("LA", "Laos", 19.86, 102.50),
    c("LB", "Lebanon", 33.85, 35.86), c("LC", "Saint Lucia", 13.91, -60.98),
    c("LI", "Liechtenstein", 47.17, 9.56), c("LK", "Sri Lanka", 7.87, 80.77),
    c("LR", "Liberia", 6.43, -9.43), c("LS", "Lesotho", -29.61, 28.23),
    c("LT", "Lithuania", 55.17, 23.88), c("LU", "Luxembourg", 49.82, 6.13),
    c("LV", "Latvia", 56.88, 24.60), c("LY", "Libya", 26.34, 17.23),
    c("MA", "Morocco", 31.79, -7.09), c("MC", "Monaco", 43.75, 7.41),
    c("MD", "Moldova", 47.41, 28.37), c("ME", "Montenegro", 42.71, 19.37),
    c("MF", "Saint Martin", 18.08, -63.05), c("MG", "Madagascar", -18.77, 46.87),
    c("MH", "Marshall Islands", 7.13, 171.18), c("MK", "North Macedonia", 41.61, 21.75),
    c("ML", "Mali", 17.57, -4.00), c("MM", "Myanmar", 21.91, 95.96),
    c("MN", "Mongolia", 46.86, 103.85), c("MO", "Macao", 22.20, 113.54),
    c("MP", "Northern Mariana Islands", 17.33, 145.38), c("MQ", "Martinique", 14.64, -61.02),
    c("MR", "Mauritania", 21.01, -10.94), c("MS", "Montserrat", 16.74, -62.19),
    c("MT", "Malta", 35.94, 14.38), c("MU", "Mauritius", -20.35, 57.55),
    c("MV", "Maldives", 3.20, 73.22), c("MW", "Malawi", -13.25, 34.30),
    c("MX", "Mexico", 23.63, -102.55), c("MY", "Malaysia", 4.21, 101.98),
    c("MZ", "Mozambique", -18.67, 35.53), c("NA", "Namibia", -22.96, 18.49),
    c("NC", "New Caledonia", -20.90, 165.62), c("NE", "Niger", 17.61, 8.08),
    c("NF", "Norfolk Island", -29.04, 167.95), c("NG", "Nigeria", 9.08, 8.68),
    c("NI", "Nicaragua", 12.87, -85.21), c("NL", "Netherlands", 52.13, 5.29),
    c("NO", "Norway", 60.47, 8.47), c("NP", "Nepal", 28.39, 84.12),
    c("NR", "Nauru", -0.52, 166.93), c("NU", "Niue", -19.05, -169.87),
    c("NZ", "New Zealand", -40.90, 174.89), c("OM", "Oman", 21.51, 55.92),
    c("PA", "Panama", 8.54, -80.78), c("PE", "Peru", -9.19, -75.02),
    c("PF", "French Polynesia", -17.68, -149.41), c("PG", "Papua New Guinea", -6.31, 143.96),
    c("PH", "Philippines", 12.88, 121.77), c("PK", "Pakistan", 30.38, 69.35),
    c("PL", "Poland", 51.92, 19.15), c("PM", "Saint Pierre and Miquelon", 46.94, -56.27),
    c("PN", "Pitcairn Islands", -24.70, -127.44), c("PR", "Puerto Rico", 18.22, -66.59),
    c("PS", "Palestine", 31.95, 35.23), c("PT", "Portugal", 39.40, -8.22),
    c("PW", "Palau", 7.51, 134.58), c("PY", "Paraguay", -23.44, -58.44),
    c("QA", "Qatar", 25.35, 51.18), c("RE", "Réunion", -21.12, 55.54),
    c("RO", "Romania", 45.94, 24.97), c("RS", "Serbia", 44.02, 21.01),
    c("RU", "Russia", 61.52, 105.32), c("RW", "Rwanda", -1.94, 29.87),
    c("SA", "Saudi Arabia", 23.89, 45.08), c("SB", "Solomon Islands", -9.65, 160.16),
    c("SC", "Seychelles", -4.68, 55.49), c("SD", "Sudan", 12.86, 30.22),
    c("SE", "Sweden", 60.13, 18.64), c("SG", "Singapore", 1.35, 103.82),
    c("SH", "Saint Helena", -24.14, -10.03), c("SI", "Slovenia", 46.15, 15.00),
    c("SJ", "Svalbard and Jan Mayen", 77.55, 23.67), c("SK", "Slovakia", 48.67, 19.70),
    c("SL", "Sierra Leone", 8.46, -11.78), c("SM", "San Marino", 43.94, 12.46),
    c("SN", "Senegal", 14.50, -14.45), c("SO", "Somalia", 5.15, 46.20),
    c("SR", "Suriname", 3.92, -56.03), c("SS", "South Sudan", 7.86, 29.69),
    c("ST", "São Tomé and Príncipe", 0.19, 6.61), c("SV", "El Salvador", 13.79, -88.90),
    c("SX", "Sint Maarten", 18.04, -63.07), c("SY", "Syria", 34.80, 39.00),
    c("SZ", "Eswatini", -26.52, 31.47), c("TC", "Turks and Caicos Islands", 21.69, -71.80),
    c("TD", "Chad", 15.45, 18.73), c("TF", "French Southern Territories", -49.28, 69.35),
    c("TG", "Togo", 8.62, 0.82), c("TH", "Thailand", 15.87, 100.99),
    c("TJ", "Tajikistan", 38.86, 71.28), c("TK", "Tokelau", -8.97, -171.86),
    c("TL", "Timor-Leste", -8.87, 125.73), c("TM", "Turkmenistan", 38.97, 59.56),
    c("TN", "Tunisia", 33.89, 9.54), c("TO", "Tonga", -21.18, -175.20),
    c("TR", "Türkiye", 38.96, 35.24), c("TT", "Trinidad and Tobago", 10.69, -61.22),
    c("TV", "Tuvalu", -7.11, 177.65), c("TW", "Taiwan", 23.70, 120.96),
    c("TZ", "Tanzania", -6.37, 34.89), c("UA", "Ukraine", 48.38, 31.17),
    c("UG", "Uganda", 1.37, 32.29), c("UM", "U.S. Outlying Islands", 19.28, 166.65),
    c("US", "United States", 37.09, -95.71), c("UY", "Uruguay", -32.52, -55.77),
    c("UZ", "Uzbekistan", 41.38, 64.59), c("VA", "Vatican City", 41.90, 12.45),
    c("VC", "Saint Vincent and the Grenadines", 12.98, -61.29), c("VE", "Venezuela", 6.42, -66.59),
    c("VG", "British Virgin Islands", 18.42, -64.64), c("VI", "U.S. Virgin Islands", 18.34, -64.90),
    c("VN", "Vietnam", 14.06, 108.28), c("VU", "Vanuatu", -15.38, 166.96),
    c("WF", "Wallis and Futuna", -13.77, -177.16), c("WS", "Samoa", -13.76, -172.10),
    c("YE", "Yemen", 15.55, 48.52), c("YT", "Mayotte", -12.83, 45.17),
    c("ZA", "South Africa", -30.56, 22.94), c("ZM", "Zambia", -13.13, 27.85),
    c("ZW", "Zimbabwe", -19.02, 29.15),
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn table_is_well_formed() {
        assert_eq!(COUNTRIES.len(), 249);
        let codes: HashSet<_> = COUNTRIES.iter().map(|c| c.code).collect();
        assert_eq!(codes.len(), COUNTRIES.len(), "duplicate codes");
        for c in COUNTRIES {
            assert!(c.code.len() == 2 && c.code.bytes().all(|b| b.is_ascii_uppercase()));
            assert!((-90.0..=90.0).contains(&c.lat) && (-180.0..=180.0).contains(&c.lon));
        }
        let mut sorted: Vec<_> = COUNTRIES.iter().map(|c| c.code).collect();
        sorted.sort_unstable();
        assert_eq!(sorted, COUNTRIES.iter().map(|c| c.code).collect::<Vec<_>>());
    }

    #[test]
    fn lookups() {
        assert_eq!(lookup("CO").map(|c| c.name), Some("Colombia"));
        assert_eq!(lookup("co").map(|c| c.code), Some("CO"));
        assert_eq!(canonical("UK"), Some("GB"));
        assert_eq!(canonical("EL"), Some("GR"));
        assert!(lookup("XK").is_none());
        assert!(lookup("ZZ").is_none());
    }
}
