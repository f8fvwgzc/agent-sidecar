//! Opt-in CPU profiling for performance work (`--features profiling`). With
//! `AGENTSC_PROFILE=<prefix>` set, the process is sampled from start-up and, at shutdown, writes
//! `<prefix>.svg` (a flamegraph) and `<prefix>.folded` (one `frame;frame;... count` line per
//! stack, for analysis). Without the feature this module is empty and costs nothing.

#[cfg(feature = "profiling")]
pub struct Profiler {
    guard: pprof::ProfilerGuard<'static>,
    prefix: String,
}

#[cfg(feature = "profiling")]
impl Profiler {
    /// Start sampling at 997 Hz when `AGENTSC_PROFILE` is set.
    pub fn from_env() -> Option<Self> {
        let prefix = std::env::var("AGENTSC_PROFILE")
            .ok()
            .filter(|p| !p.is_empty())?;
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(997)
            .blocklist(&["libc", "libgcc", "pthread", "vdso", "libsystem"])
            .build()
            .map_err(|e| tracing::warn!("profiling not started: {e}"))
            .ok()?;
        tracing::info!(%prefix, "CPU profiling started");
        Some(Self { guard, prefix })
    }

    /// Write `<prefix>.svg` and `<prefix>.folded`.
    pub fn finish(self) {
        let report = match self.guard.report().build() {
            Ok(r) => r,
            Err(e) => return tracing::warn!("profile report failed: {e}"),
        };
        let svg = format!("{}.svg", self.prefix);
        match std::fs::File::create(&svg) {
            Ok(f) => {
                if let Err(e) = report.flamegraph(f) {
                    tracing::warn!("flamegraph failed: {e}");
                }
            }
            Err(e) => tracing::warn!(path = %svg, "flamegraph file: {e}"),
        }
        let mut folded = String::new();
        for (frames, count) in &report.data {
            let mut names: Vec<String> = Vec::new();
            for frame in frames.frames.iter().rev() {
                for symbol in frame.iter().rev() {
                    names.push(symbol.name().replace(';', ":"));
                }
            }
            folded.push_str(&format!(
                "{};{} {count}\n",
                frames.thread_name,
                names.join(";")
            ));
        }
        let path = format!("{}.folded", self.prefix);
        if let Err(e) = std::fs::write(&path, folded) {
            tracing::warn!(%path, "folded stacks: {e}");
        }
        tracing::info!(%svg, "CPU profile written");
    }
}

#[cfg(not(feature = "profiling"))]
pub struct Profiler;

#[cfg(not(feature = "profiling"))]
impl Profiler {
    pub fn from_env() -> Option<Self> {
        None
    }
    pub fn finish(self) {}
}
