use std::fmt;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiveDiagnostics {
    pub packets_received: usize,
    pub packets_accepted: usize,
    pub decode_errors: usize,
    pub auth_rejections: usize,
    pub replay_rejections: usize,
    pub metadata_rejections: usize,
    pub source_rejections: usize,
    pub duplicate_packets: usize,
    pub pending_budget_rejections: usize,
    pub session_budget_rejections: usize,
}

impl ReceiveDiagnostics {
    pub fn rejected_packets(&self) -> usize {
        self.decode_errors
            .saturating_add(self.auth_rejections)
            .saturating_add(self.replay_rejections)
            .saturating_add(self.metadata_rejections)
            .saturating_add(self.source_rejections)
            .saturating_add(self.pending_budget_rejections)
            .saturating_add(self.session_budget_rejections)
    }

    pub fn has_rejected_traffic(&self) -> bool {
        self.rejected_packets() > 0
    }
}

impl fmt::Display for ReceiveDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return write!(
                f,
                "recv={}\naccepted={}\nrejected={}\ndecode={}\nauth={}\nreplay={}\nmetadata={}\nsource={}\nduplicate={}\nbudget={}\nsession_budget={}",
                self.packets_received,
                self.packets_accepted,
                self.rejected_packets(),
                self.decode_errors,
                self.auth_rejections,
                self.replay_rejections,
                self.metadata_rejections,
                self.source_rejections,
                self.duplicate_packets,
                self.pending_budget_rejections,
                self.session_budget_rejections
            );
        }
        write!(
            f,
            "recv={}, accepted={}, rejected={}, decode={}, auth={}, replay={}, metadata={}, source={}, duplicate={}, budget={}, session_budget={}",
            self.packets_received,
            self.packets_accepted,
            self.rejected_packets(),
            self.decode_errors,
            self.auth_rejections,
            self.replay_rejections,
            self.metadata_rejections,
            self.source_rejections,
            self.duplicate_packets,
            self.pending_budget_rejections,
            self.session_budget_rejections
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ReceiveDiagnostics;

    #[test]
    fn receive_diagnostics_display_compact_is_labeled() {
        let diagnostics = ReceiveDiagnostics {
            packets_received: 10,
            packets_accepted: 6,
            decode_errors: 1,
            auth_rejections: 2,
            replay_rejections: 3,
            metadata_rejections: 4,
            source_rejections: 5,
            duplicate_packets: 7,
            pending_budget_rejections: 8,
            session_budget_rejections: 9,
        };
        let rendered = diagnostics.to_string();
        assert!(rendered.contains("recv=10"));
        assert!(rendered.contains("accepted=6"));
        assert!(rendered.contains("rejected=32"));
        assert!(rendered.contains("duplicate=7"));
        assert!(rendered.contains("budget=8"));
        assert!(rendered.contains("session_budget=9"));
    }

    #[test]
    fn receive_diagnostics_display_alternate_is_multiline() {
        let diagnostics = ReceiveDiagnostics {
            packets_received: 1,
            packets_accepted: 1,
            decode_errors: 0,
            auth_rejections: 0,
            replay_rejections: 0,
            metadata_rejections: 0,
            source_rejections: 0,
            duplicate_packets: 0,
            pending_budget_rejections: 0,
            session_budget_rejections: 0,
        };
        let rendered = format!("{diagnostics:#}");
        assert!(rendered.contains("recv=1\naccepted=1"));
        assert!(rendered.contains("rejected=0"));
    }
}
