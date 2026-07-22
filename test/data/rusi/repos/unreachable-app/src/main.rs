// Unreachable-app: the Cargo BOM lists sqlx as a dependency, but the source
// NEVER calls into it. rusi therefore produces no call-graph edge and no
// dataflow slice touching sqlx, so the converter emits no flow carrying
// pkg:cargo/sqlx@<v>. FrameworkReachability must NOT mark sqlx reached.
fn main() {
    let greeting = "hello";
    println!("{}", greeting);
}
