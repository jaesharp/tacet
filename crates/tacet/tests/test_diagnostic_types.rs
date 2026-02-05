// Integration test for new diagnostic types
// Run with: cargo test --test test_diagnostic_types

#[test]
fn test_effect_pattern_display() {
    use tacet::EffectPattern;

    assert_eq!(EffectPattern::TailEffect.to_string(), "tail effect");
    assert_eq!(EffectPattern::UniformShift.to_string(), "uniform shift");
    assert_eq!(EffectPattern::Mixed.to_string(), "mixed pattern");
    assert_eq!(EffectPattern::Negligible.to_string(), "negligible");
}

#[test]
fn test_quantile_shifts_creation() {
    use tacet::QuantileShifts;

    let shifts = QuantileShifts {
        p50_ns: 10.0,
        p90_ns: 20.0,
        p95_ns: 30.0,
        p99_ns: 50.0,
    };

    assert_eq!(shifts.p50_ns, 10.0);
    assert_eq!(shifts.p90_ns, 20.0);
    assert_eq!(shifts.p95_ns, 30.0);
    assert_eq!(shifts.p99_ns, 50.0);
}

#[test]
fn test_tail_diagnostics_creation() {
    use tacet::{EffectPattern, QuantileShifts, TailDiagnostics};

    let shifts = QuantileShifts {
        p50_ns: 10.0,
        p90_ns: 20.0,
        p95_ns: 30.0,
        p99_ns: 50.0,
    };

    let tail_diag = TailDiagnostics {
        shift_ns: 15.0,
        tail_ns: 5.0,
        tail_share: 0.25,
        tail_slow_share: 0.6,
        quantile_shifts: shifts,
        pattern_label: EffectPattern::UniformShift,
    };

    assert_eq!(tail_diag.shift_ns, 15.0);
    assert_eq!(tail_diag.tail_ns, 5.0);
    assert_eq!(tail_diag.tail_share, 0.25);
    assert_eq!(tail_diag.tail_slow_share, 0.6);
    assert_eq!(tail_diag.pattern_label, EffectPattern::UniformShift);
}

#[test]
fn test_serde_serialization() {
    use tacet::{EffectPattern, QuantileShifts, TailDiagnostics};

    let shifts = QuantileShifts {
        p50_ns: 10.0,
        p90_ns: 20.0,
        p95_ns: 30.0,
        p99_ns: 50.0,
    };

    let tail_diag = TailDiagnostics {
        shift_ns: 15.0,
        tail_ns: 5.0,
        tail_share: 0.25,
        tail_slow_share: 0.6,
        quantile_shifts: shifts,
        pattern_label: EffectPattern::TailEffect,
    };

    // Test JSON serialization
    let json = serde_json::to_string(&tail_diag).expect("Should serialize to JSON");
    assert!(json.contains("shift_ns"));
    assert!(json.contains("tail_ns"));
    assert!(json.contains("TailEffect"));

    // Test JSON deserialization
    let deserialized: TailDiagnostics =
        serde_json::from_str(&json).expect("Should deserialize from JSON");
    assert_eq!(deserialized.shift_ns, tail_diag.shift_ns);
    assert_eq!(deserialized.tail_ns, tail_diag.tail_ns);
    assert_eq!(deserialized.pattern_label, tail_diag.pattern_label);
}
