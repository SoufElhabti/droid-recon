# Source-to-sink benchmark

Eight small Java examples exercise four source-to-sink classes: WebView URL loading,
command execution, Intent redirection, and SQL construction. Each pair has an
unguarded example and a corrected or guarded example. The test suite counts a
`no_guard_seen` candidate as an alert. `guard_seen` remains in the analysis for
manual review because finding a nearby check does not prove it is effective.

The corpus is intentionally small. Its confusion matrix measures regressions in
these examples, not detection performance on real APKs or proof of a vulnerability.
