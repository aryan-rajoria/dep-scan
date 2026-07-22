// rustsec-app: a REAL vulnerable dependency (time 0.1.x, RUSTSEC-2020-0071)
// called on a tainted path. Proves the rusi slice -> reached_purls -> VDR
// insight loop end-to-end: the vulnerable crate MUST be marked Reachable in
// the VDR because the source calls time::now(), while a crate that is merely
// present in the BOM but never called is NOT marked reachable.
use std::env;

fn main() {
    // tainted source: environment influence
    let tz = env::var("TZ").unwrap_or_else(|_| "UTC".to_string());
    // sink: the vulnerable time API is reached with tainted influence
    let _now = time::now();
    let _tz = tz.as_str();
}
