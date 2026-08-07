//! Render a run's reasoning trace as a shareable artifact (Markdown or HTML).
//!
//! The [`RunReport`] already carries the full, replayable agentic state; this
//! module turns it into something a human reviewer (or a PR comment) can read
//! without a terminal. Both renderers draw from the *same* [`FeedbackFormatter`]
//! output the run itself used, so the published trace cannot drift from what
//! the agent actually saw.

use tpt_nexus_orchestrator::{FeedbackFormatter, RunReport};

/// Render the trace as GitHub-flavored Markdown.
///
/// Suitable for dropping into a PR comment or a build artifact.
pub fn render_trace_markdown(report: &RunReport) -> String {
    let fmt = FeedbackFormatter::new();
    let mut out = String::from("# Nexus reasoning trace\n\n");
    out.push_str(&fmt.summary(&report.context));
    out.push_str("\n\n");

    for func in &report.context.functions {
        out.push_str(&format!("## `{}`\n\n", func.func_name));
        out.push_str("```text\n");
        out.push_str(&fmt.function(func));
        out.push_str("\n```\n\n");
    }
    out
}

/// Render the trace as a self-contained HTML page.
pub fn render_trace_html(report: &RunReport) -> String {
    let fmt = FeedbackFormatter::new();
    let mut out =
        String::from("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<title>Nexus reasoning trace</title>\n");
    out.push_str("<style>\n");
    out.push_str("body{font-family:monospace;margin:2rem;line-height:1.4}\n");
    out.push_str("h1{font-size:1.4rem}pre{background:#f4f4f4;padding:1rem;border-radius:6px;overflow:auto}\n");
    out.push_str("code{color:#0a0}.fail{color:#b00}.pass{color:#070}\n");
    out.push_str("</style>\n</head>\n<body>\n");
    out.push_str("<h1>Nexus reasoning trace</h1>\n");
    out.push_str("<pre>");
    out.push_str(&escape(&fmt.summary(&report.context)));
    out.push_str("</pre>\n");

    for func in &report.context.functions {
        out.push_str(&format!(
            "<h2><code>{}</code></h2>\n",
            escape(&func.func_name)
        ));
        out.push_str("<pre>");
        out.push_str(&escape(&fmt.function(func)));
        out.push_str("</pre>\n");
    }
    out.push_str("</body>\n</html>\n");
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};

    const INTENT: &str = r#"
        module Counter {
            invariant Counter { value >= 0 }
            func increment(c: Counter, by: PositiveInt)
                requires c.value >= 0
                ensures c.value == old(c.value) + by
            ;
        }
    "#;

    #[test]
    fn markdown_and_html_are_produced_and_differ() {
        let artifact = NexusOrchestrator::new()
            .run_agent_loop(INTENT, &StaticAgent::new())
            .unwrap();
        let md = render_trace_markdown(&artifact.report);
        let html = render_trace_html(&artifact.report);
        assert!(md.contains("Nexus reasoning trace"));
        assert!(md.contains("increment"));
        assert!(html.contains("<html"));
        assert!(html.contains("increment"));
        assert!(html.contains("&lt;") || html.contains("<pre>"));
        assert_ne!(md, html);
    }
}
