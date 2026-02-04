// Debug script to trace through IACT computation
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

fn geyer_ims_iact_debug(u: &[f64]) {
    let n = u.len();
    println!("n = {}", n);

    // Compute mean and center data
    let mean = u.iter().sum::<f64>() / n as f64;
    let centered: Vec<f64> = u.iter().map(|&x| x - mean).collect();
    println!("mean = {}", mean);

    // Compute variance
    let var = centered.iter().map(|x| x * x).sum::<f64>() / n as f64;
    println!("var = {}", var);

    // Compute autocorrelations
    let max_lag = (n / 4).min(1000);
    println!("max_lag = {}", max_lag);

    let mut rho = vec![0.0; max_lag + 1];
    rho[0] = 1.0;

    for k in 1..=max_lag.min(10) {
        let cross_product: f64 = centered[k..]
            .iter()
            .zip(centered[..n - k].iter())
            .map(|(&a, &b)| a * b)
            .sum();
        rho[k] = cross_product / (n as f64 * var);
        println!("ρ[{}] = {:.6}", k, rho[k]);
    }

    // Form pairs
    let m_max = (max_lag - 1) / 2;
    println!("\nm_max = {}", m_max);

    let mut gamma = vec![0.0; m_max + 1];
    for m in 0..=m_max.min(5) {
        let idx1 = 2 * m;
        let idx2 = 2 * m + 1;
        if idx2 <= max_lag {
            gamma[m] = rho[idx1] + rho[idx2];
            println!("Γ[{}] = ρ[{}] + ρ[{}] = {:.6} + {:.6} = {:.6}",
                     m, idx1, idx2, rho[idx1], rho[idx2], gamma[m]);
        }
    }

    // Enforce monotonicity
    println!("\nAfter monotone enforcement:");
    for m in 1..=m_max.min(5) {
        let old_val = gamma[m];
        gamma[m] = gamma[m].min(gamma[m - 1]);
        println!("Γ[{}] = min({:.6}, {:.6}) = {:.6}",
                 m, old_val, gamma[m-1], gamma[m]);
    }

    // Truncation
    let mut m_trunc = 0;
    for m in 1..=m_max {
        if gamma[m] <= 0.0 {
            break;
        }
        m_trunc = m;
    }
    println!("\nm_trunc = {}", m_trunc);

    // Compute tau
    let gamma_sum: f64 = gamma[0..=m_trunc].iter().sum();
    println!("sum(Γ[0..{}]) = {:.6}", m_trunc, gamma_sum);

    let tau = (-1.0 + 2.0 * gamma_sum).max(1.0);
    println!("τ = max(1.0, -1 + 2 * {:.6}) = {:.6}", gamma_sum, tau);
}

fn main() {
    println!("=== Testing with IID data (should give tau ~1.0) ===\n");
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(42);
    let data: Vec<f64> = (0..500).map(|_| rng.random()).collect();
    geyer_ims_iact_debug(&data);

    println!("\n\n=== Testing with AR(1) phi=0.5 (should give tau ~3.0) ===\n");
    let phi = 0.5;
    let mut rng2 = Xoshiro256PlusPlus::seed_from_u64(123);
    let mut ar_data = Vec::with_capacity(1000);
    let mut x = 0.0;
    for _ in 0..1000 {
        x = phi * x + rng2.random::<f64>() - 0.5;
        ar_data.push(x);
    }
    geyer_ims_iact_debug(&ar_data);
}
