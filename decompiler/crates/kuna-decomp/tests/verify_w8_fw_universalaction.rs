//! Behavioral verification of universal-action filtering.
//!
//! An empty or unmatched group selection must drop the entire schedule rather
//! than leave containers that could execute disabled analysis passes.

use kuna_decomp::universalaction::{universal_sched, ActionListFilter};

#[test]
fn w8_fw_universalaction_empty_or_unmatched_filter_drops_whole_tree() {
    let empty = ActionListFilter::from_names(Vec::<String>::new());
    let none = universal_sched(None, None, vec![]).list_action_dump(&empty);
    assert_eq!(none, "", "empty filter must render nothing (root drops)");

    // A single group that no leaf carries: still empty.  ("xyzzy" is not a real
    // group; even `start` is group "base".)
    let bogus = ActionListFilter::from_names(["xyzzy_not_a_group"]);
    let none2 = universal_sched(None, None, vec![]).list_action_dump(&bogus);
    assert_eq!(none2, "", "unmatched filter must render nothing");
}
