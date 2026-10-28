//! UTC times as agents read them.

use serde_json::Value;

/// `2026-10-27T14:35:33Z` (UTC, seconds).
pub fn iso_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Unix seconds that look like a real time (2001..2286), not a count.
fn plausible(n: u64) -> bool {
    (1_000_000_000..10_000_000_000).contains(&n)
}

/// Give every Unix time in `v` (a key ending in `_at`, any depth) a
/// readable `<key>_utc` sibling, unless it already has one. `null` stays
/// `null` (`<key>_utc: null`).
pub fn add_utc_siblings(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let add: Vec<(String, Value)> = map
                .iter()
                .filter(|(k, _)| k.ends_with("_at") && !map.contains_key(&format!("{k}_utc")))
                .filter_map(|(k, val)| match val {
                    Value::Number(n) => n
                        .as_u64()
                        .filter(|n| plausible(*n))
                        .map(|n| (format!("{k}_utc"), Value::String(iso_utc(n)))),
                    Value::Null => Some((format!("{k}_utc"), Value::Null)),
                    _ => None,
                })
                .collect();
            for val in map.values_mut() {
                add_utc_siblings(val);
            }
            for (k, val) in add {
                map.insert(k, val);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(add_utc_siblings),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_unix_time_gets_a_utc_sibling() {
        let mut v = json!({
            "created_at": 1_761_600_000u64,
            "revoked_at": null,
            "expires_at": 1_761_600_000u64,
            "expires_at_utc": "kept",
            "count_at": 3,
            "invites": [{ "requested_at": 1_761_600_000u64 }],
        });
        add_utc_siblings(&mut v);
        assert_eq!(v["created_at_utc"], "2025-10-27T21:20:00Z");
        assert!(v["revoked_at_utc"].is_null() && v.get("revoked_at_utc").is_some());
        assert_eq!(v["expires_at_utc"], "kept");
        assert!(v.get("count_at_utc").is_none());
        assert_eq!(v["invites"][0]["requested_at_utc"], "2025-10-27T21:20:00Z");
    }
}
