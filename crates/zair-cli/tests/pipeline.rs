//! Full pipeline integration tests exercising the end-to-end CLI workflow.

mod test_utils;

use test_utils::pipeline_harness::run_pipeline;

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn pipeline_native() {
    run_pipeline("native");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn pipeline_sha256() {
    run_pipeline("sha256");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn pipeline_plain() {
    run_pipeline("plain");
}
