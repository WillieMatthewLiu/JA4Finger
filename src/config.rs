use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use serde::Deserialize;

const DEFAULT_DAEMON_LOG_DIR: &str = "logs";
const DEFAULT_DAEMON_LOG_FILE: &str = "ja4finger.log";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonRuntimeConfig {
    pub iface: String,
    pub src_excludes: ExclusionMatcher,
    pub dst_excludes: ExclusionMatcher,
    pub log_dir: String,
    pub log_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExclusionMatcher {
    rules: Vec<ExcludeRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExcludeRule {
    Ip(IpAddr),
    Cidr(IpNet),
}

impl ExclusionMatcher {
    pub fn from_rules(rules: &[String]) -> Result<Self, String> {
        Self::from_rules_with_name("excludes", rules)
    }

    fn from_rules_with_name(name: &str, rules: &[String]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            compiled.push(parse_rule(name, rule)?);
        }
        Ok(Self { rules: compiled })
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        self.rules.iter().any(|rule| match rule {
            ExcludeRule::Ip(exact) => *exact == ip,
            ExcludeRule::Cidr(network) => network.contains(&ip),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootConfig {
    daemon: DaemonYamlConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonYamlConfig {
    iface: String,
    #[serde(default)]
    src_excludes: Vec<String>,
    #[serde(default)]
    dst_excludes: Vec<String>,
    #[serde(default = "default_log_dir")]
    log_dir: String,
    #[serde(default = "default_log_file")]
    log_file: String,
}

fn default_log_dir() -> String {
    DEFAULT_DAEMON_LOG_DIR.to_string()
}

fn default_log_file() -> String {
    DEFAULT_DAEMON_LOG_FILE.to_string()
}

fn parse_rule(name: &str, rule: &str) -> Result<ExcludeRule, String> {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return Err(format!("{name} contains empty rule"));
    }

    if trimmed.contains('/') {
        let network = trimmed
            .parse::<IpNet>()
            .map_err(|err| format!("invalid {name} CIDR entry `{trimmed}`: {err}"))?;
        return Ok(ExcludeRule::Cidr(network));
    }

    let ip = trimmed
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid {name} IP entry `{trimmed}`: {err}"))?;
    Ok(ExcludeRule::Ip(ip))
}

pub fn parse_daemon_config(yaml: &str) -> Result<DaemonRuntimeConfig, String> {
    let root = serde_yaml::from_str::<RootConfig>(yaml)
        .map_err(|err| format!("invalid daemon config yaml: {err}"))?;

    let iface = root.daemon.iface.trim();
    if iface.is_empty() {
        return Err("invalid daemon config: `daemon.iface` cannot be empty".to_string());
    }

    let src_excludes =
        ExclusionMatcher::from_rules_with_name("src_excludes", &root.daemon.src_excludes)?;
    let dst_excludes =
        ExclusionMatcher::from_rules_with_name("dst_excludes", &root.daemon.dst_excludes)?;

    let log_dir = root.daemon.log_dir.trim();
    if log_dir.is_empty() {
        return Err("invalid daemon config: `daemon.log_dir` cannot be empty".to_string());
    }

    let log_file = root.daemon.log_file.trim();
    if log_file.is_empty() {
        return Err("invalid daemon config: `daemon.log_file` cannot be empty".to_string());
    }

    Ok(DaemonRuntimeConfig {
        iface: iface.to_string(),
        src_excludes,
        dst_excludes,
        log_dir: log_dir.to_string(),
        log_file: log_file.to_string(),
    })
}

pub fn load_daemon_config(path: &Path) -> Result<DaemonRuntimeConfig, String> {
    let yaml = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read config file {}: {err}", path.display()))?;
    parse_daemon_config(&yaml)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{ExclusionMatcher, parse_daemon_config};

    #[test]
    fn parse_daemon_config_accepts_iface_and_exclusion_lists() {
        let yaml = r#"
daemon:
  iface: eth0
  src_excludes: [127.0.0.1, 10.0.0.0/8]
  dst_excludes: [192.168.1.100, 172.16.0.0/12]
"#;

        let parsed = parse_daemon_config(yaml).expect("yaml should parse");

        assert_eq!(parsed.iface, "eth0");
        assert_eq!(parsed.log_dir, "logs");
        assert_eq!(parsed.log_file, "ja4finger.log");
        assert!(
            parsed
                .src_excludes
                .matches(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4))),
            "cidr source rule should match"
        );
        assert!(
            !parsed
                .src_excludes
                .matches(IpAddr::V4(Ipv4Addr::new(11, 2, 3, 4))),
            "out-of-range source should not match"
        );
        assert!(
            parsed
                .dst_excludes
                .matches(IpAddr::V4(Ipv4Addr::new(172, 16, 99, 1))),
            "cidr destination rule should match"
        );
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_exclusion_rule() {
        let yaml = r#"
daemon:
  iface: eth0
  src_excludes: [10.0.0.0/99]
  dst_excludes: []
"#;

        let err = parse_daemon_config(yaml).expect_err("invalid cidr should fail");
        assert!(
            err.contains("src_excludes"),
            "error should mention source excludes: {err}"
        );
    }

    #[test]
    fn exclusion_matcher_matches_single_ip_and_cidr() {
        let matcher =
            ExclusionMatcher::from_rules(&["127.0.0.1".to_string(), "10.0.0.0/8".to_string()])
                .expect("rules should parse");

        assert!(
            matcher.matches(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            "single ip should match"
        );
        assert!(
            matcher.matches(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))),
            "cidr should match"
        );
        assert!(
            !matcher.matches(IpAddr::V4(Ipv4Addr::new(11, 20, 30, 40))),
            "non matching ip should not match"
        );
    }
}
