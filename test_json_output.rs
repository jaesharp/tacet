// Quick test to verify JSON structure
use tacet::result::{Outcome, EffectEstimate, MeasurementQuality, Diagnostics, Exploitability, EffectPattern, QuantileShifts, TailDiagnostics};
use tacet::output::json::to_json_pretty;

fn main() {
    let outcome = Outcome::Fail {
        leak_probability: 0.98,
        effect: EffectEstimate::with_tail_diagnostics(
            150.0,
            (100.0, 200.0),
            TailDiagnostics {
                shift_ns: 120.0,
                tail_ns: 30.0,
                tail_share: 0.2,
                tail_slow_share: 0.8,
                quantile_shifts: QuantileShifts {
                    p50_ns: 115.0,
                    p90_ns: 145.0,
                    p95_ns: 160.0,
                    p99_ns: 180.0,
                },
                pattern_label: EffectPattern::UniformShift,
            },
        ),
        exploitability: Exploitability::Http2Multiplexing,
        samples_used: 10000,
        quality: MeasurementQuality::Good,
        diagnostics: Diagnostics::all_ok(),
        theta_user: 100.0,
        theta_eff: 100.0,
        theta_floor: 0.0,
    };

    let json = to_json_pretty(&outcome).unwrap();
    println!("{}", json);
}
