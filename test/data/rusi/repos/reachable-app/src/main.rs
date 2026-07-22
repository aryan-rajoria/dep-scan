// Reachable-app: calls the external sqlx crate on a file -> sql-query taint
// path. rusi must produce a dataflow slice + a call-graph edge to sqlx, which
// the dep-scan converter reconciles onto the Cargo BOM's versioned
// pkg:cargo/sqlx@<v> purl so FrameworkReachability marks it reached.
use std::fs;

fn main() {
    // source: tainted file input
    let db_key = fs::read_to_string("/var/tmp/tainted_file.txt").unwrap();
    // sink: the tainted value flows into a sqlx query (file-to-sql-query rule)
    let tainted_query = format!(
        "SELECT * FROM someTable WHERE key = '{}'",
        db_key.trim()
    );
    let _ = sqlx::query(&tainted_query).fetch_one(&pool);
}
