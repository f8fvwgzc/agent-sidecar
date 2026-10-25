//! The one price table (CONTRACT.md §9): USD per 1M tokens, Anthropic API list prices (cached
//! 2026-10-06). The sidecar's model gateway prices every call from the usage the provider itself
//! reported; nothing the runtime says about cost is used. `mock` costs nothing.

/// (input, output) USD per 1M tokens.
const PRICES: &[(&str, (f64, f64))] = &[
    ("claude-fable-5-1", (10.00, 50.00)),
    ("claude-mythos-5-1", (10.00, 50.00)),
    ("claude-fable-5", (10.00, 50.00)),
    ("claude-opus-5-5", (4.00, 20.00)),
    ("claude-opus-5", (5.00, 25.00)),
    ("claude-opus-4-8", (5.00, 25.00)),
    ("claude-opus-4-7", (5.00, 25.00)),
    ("claude-opus-4-6", (5.00, 25.00)),
    ("claude-sonnet-5-5", (2.00, 10.00)),
    ("claude-sonnet-5", (2.00, 10.00)),
    ("claude-sonnet-4-6", (3.00, 15.00)),
    ("claude-haiku-5-5", (0.10, 0.50)),
    ("claude-haiku-4-5", (1.00, 5.00)),
    ("mock", (0.0, 0.0)),
];

/// Unknown model ids are priced like the most expensive tier, so a budget never under-counts.
const FALLBACK: (f64, f64) = (10.00, 50.00);

/// Claude Haiku 5.5 is priced higher for prompts above 100K tokens (the whole request at the
/// higher rate). The prompt is every input token, cached or not.
const LONG_PROMPT: &[(&str, u64, (f64, f64))] = &[("claude-haiku-5-5", 100_000, (0.50, 2.50))];

/// Cache reads as a fraction of the input rate: 0.1 unless listed.
const CACHE_READ: &[(&str, f64)] = &[
    ("claude-fable-5-1", 0.025),
    ("claude-mythos-5-1", 0.025),
    ("claude-opus-5-5", 0.05),
];
const CACHE_READ_DEFAULT: f64 = 0.1;
/// Cache writes as a multiple of the input rate: 5-minute and 1-hour entries. A write the
/// provider did not break down by TTL is priced as a 1-hour write (the dearer one).
const CACHE_WRITE_5M: f64 = 1.25;
const CACHE_WRITE_1H: f64 = 2.0;

/// The token counts of one model call, as the provider reported them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Uncached input tokens.
    pub input: u64,
    pub output: u64,
    /// Input tokens written to the prompt cache, by TTL; `cache_write_unknown` when the provider
    /// gave only the total.
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    pub cache_write_unknown: u64,
    pub cache_read: u64,
}

impl Usage {
    /// Every input token of the request: uncached, written to and read from the cache.
    pub fn prompt_tokens(&self) -> u64 {
        self.input
            + self.cache_write_5m
            + self.cache_write_1h
            + self.cache_write_unknown
            + self.cache_read
    }
}

fn lookup<T: Copy>(table: &[(&str, T)], model: &str) -> Option<T> {
    table.iter().find(|(m, _)| *m == model).map(|(_, v)| *v)
}

/// Is `model` in the price table (`mock` included)?
pub fn is_priced(model: &str) -> bool {
    lookup(PRICES, model).is_some()
}

/// (input, output) USD per 1M tokens for `model` with a prompt of `prompt_tokens`.
pub fn rates(model: &str, prompt_tokens: u64) -> (f64, f64) {
    if let Some((_, threshold, long)) = LONG_PROMPT.iter().find(|(m, _, _)| *m == model)
        && prompt_tokens > *threshold
    {
        return *long;
    }
    lookup(PRICES, model).unwrap_or(FALLBACK)
}

/// The cost of one call, rounded to a millionth of a dollar.
pub fn cost_usd(model: &str, u: &Usage) -> f64 {
    let (inp, out) = rates(model, u.prompt_tokens());
    let read = lookup(CACHE_READ, model).unwrap_or(CACHE_READ_DEFAULT);
    let input_equivalent = u.input as f64
        + u.cache_read as f64 * read
        + u.cache_write_5m as f64 * CACHE_WRITE_5M
        + (u.cache_write_1h + u.cache_write_unknown) as f64 * CACHE_WRITE_1H;
    round6((input_equivalent * inp + u.output as f64 * out) / 1_000_000.0)
}

/// The most a call can cost before it is made: at most `prompt_tokens` input tokens, all priced
/// as 1-hour cache writes (the dearest way to send them), and `max_tokens` output tokens.
pub fn worst_case_usd(model: &str, prompt_tokens: u64, max_tokens: u64) -> f64 {
    cost_usd(
        model,
        &Usage {
            cache_write_unknown: prompt_tokens,
            output: max_tokens,
            ..Usage::default()
        },
    )
}

fn round6(usd: f64) -> f64 {
    (usd * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(input: u64, output: u64) -> Usage {
        Usage {
            input,
            output,
            ..Usage::default()
        }
    }

    #[test]
    fn list_prices_per_million_tokens() {
        assert_eq!(cost_usd("mock", &io(1000, 1000)), 0.0);
        assert_eq!(cost_usd("claude-opus-5-5", &io(1_000_000, 0)), 4.0);
        assert_eq!(cost_usd("claude-opus-5-5", &io(0, 1_000_000)), 20.0);
        assert_eq!(cost_usd("claude-haiku-5-5", &io(100_000, 100_000)), 0.06);
        assert_eq!(
            cost_usd("unknown-model", &io(1_000_000, 0)),
            10.0,
            "unknown models are priced at the top tier"
        );
        assert!(is_priced("mock") && !is_priced("unknown-model"));
    }

    #[test]
    fn long_prompts_switch_the_whole_request_to_the_higher_rate() {
        assert_eq!(cost_usd("claude-haiku-5-5", &io(100_000, 0)), 0.01);
        assert_eq!(cost_usd("claude-haiku-5-5", &io(200_000, 0)), 0.1);
        let cached = Usage {
            input: 1_000,
            cache_read: 150_000,
            ..Usage::default()
        };
        assert_eq!(
            rates("claude-haiku-5-5", cached.prompt_tokens()),
            (0.50, 2.50),
            "cached input counts toward the prompt length"
        );
    }

    #[test]
    fn cache_reads_and_writes_have_their_own_rates() {
        let u = Usage {
            cache_read: 1_000_000,
            ..Usage::default()
        };
        assert_eq!(cost_usd("claude-opus-5-5", &u), 0.2);
        assert_eq!(cost_usd("claude-fable-5-1", &u), 0.25);
        assert_eq!(cost_usd("claude-sonnet-5-5", &u), 0.2);
        let w = |m5, h1, unknown| Usage {
            cache_write_5m: m5,
            cache_write_1h: h1,
            cache_write_unknown: unknown,
            ..Usage::default()
        };
        assert_eq!(cost_usd("claude-opus-5-5", &w(1_000_000, 0, 0)), 5.0);
        assert_eq!(cost_usd("claude-opus-5-5", &w(0, 1_000_000, 0)), 8.0);
        assert_eq!(
            cost_usd("claude-opus-5-5", &w(0, 0, 1_000_000)),
            8.0,
            "a write without its TTL is priced as the dearer one"
        );
    }

    #[test]
    fn the_worst_case_bounds_every_real_usage() {
        let worst = worst_case_usd("claude-opus-5-5", 10_000, 1_024);
        for u in [
            io(10_000, 1_024),
            Usage {
                input: 4_000,
                cache_write_5m: 6_000,
                output: 1_024,
                ..Usage::default()
            },
            Usage {
                cache_read: 10_000,
                output: 1_024,
                ..Usage::default()
            },
        ] {
            assert!(cost_usd("claude-opus-5-5", &u) <= worst, "{u:?}");
        }
        assert_eq!(worst, 0.10048);
    }
}
