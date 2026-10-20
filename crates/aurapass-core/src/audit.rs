//! Vault health auditing — the "security dashboard".
//!
//! The audit is pure and deterministic: it takes a [`VaultData`] plus optional
//! breach counts and returns findings. That keeps it trivially testable and
//! usable both from the GUI and from `aurapass audit`.

use crate::model::{ItemKind, VaultData};
use crate::strength;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// How alarming a finding is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, nothing more.
    Info,
    /// Should be fixed at some point.
    Low,
    /// Should be fixed soon.
    Medium,
    /// Fix now.
    High,
    /// Fix immediately — the credential is known to be compromised.
    Critical,
}

impl Severity {
    /// Short label for badges.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// Colour as `(r, g, b)`.
    pub fn color(self) -> (u8, u8, u8) {
        match self {
            Severity::Info => (0x5b, 0x8d, 0xef),
            Severity::Low => (0x6c, 0x9e, 0x4f),
            Severity::Medium => (0xd9, 0xb8, 0x36),
            Severity::High => (0xe0, 0x84, 0x3c),
            Severity::Critical => (0xd6, 0x4b, 0x3f),
        }
    }

    /// Weight used when computing the overall score.
    fn penalty(self) -> i32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 8,
            Severity::Critical => 15,
        }
    }
}

/// The kind of problem a finding describes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// The item has no password at all.
    EmptyPassword,
    /// The password is short or guessable.
    WeakPassword,
    /// The same password guards several items.
    ReusedPassword,
    /// The password appears in a public breach corpus.
    BreachedPassword,
    /// The item's expiry date has passed.
    Expired,
    /// The password has not been changed in years.
    StalePassword,
    /// A login without two-factor authentication.
    MissingTotp,
    /// Two items look like the same account.
    Duplicate,
    /// The item has never been used.
    Unused,
}

impl FindingKind {
    /// Short label.
    pub fn label(self) -> &'static str {
        match self {
            FindingKind::EmptyPassword => "No password",
            FindingKind::WeakPassword => "Weak password",
            FindingKind::ReusedPassword => "Password reuse",
            FindingKind::BreachedPassword => "Found in a breach",
            FindingKind::Expired => "Expired",
            FindingKind::StalePassword => "Old password",
            FindingKind::MissingTotp => "No two-factor",
            FindingKind::Duplicate => "Duplicate",
            FindingKind::Unused => "Never used",
        }
    }
}

/// One problem detected by the audit.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    /// What kind of problem this is.
    pub kind: FindingKind,
    /// How urgent it is.
    pub severity: Severity,
    /// The offending item, when the finding is item-specific.
    pub item_id: Option<Uuid>,
    /// Item title, denormalised so the report is readable on its own.
    pub item_title: String,
    /// One-sentence explanation.
    pub detail: String,
    /// What the user should do about it.
    pub remediation: String,
}

/// Counts per problem class, for the dashboard tiles.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HealthCounts {
    /// Items in the vault (excluding the bin).
    pub items: usize,
    /// Items that carry a password.
    pub passwords: usize,
    /// Passwords scoring 0 or 1.
    pub weak: usize,
    /// Passwords shared by more than one item.
    pub reused: usize,
    /// Passwords found in a breach corpus.
    pub breached: usize,
    /// Passwords older than two years.
    pub stale: usize,
    /// Expired items.
    pub expired: usize,
    /// Logins without TOTP.
    pub missing_totp: usize,
    /// Duplicate groups.
    pub duplicates: usize,
}

/// The complete result of one audit run.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditReport {
    /// When the report was produced.
    pub generated_at: DateTime<Utc>,
    /// Aggregate counts.
    pub counts: HealthCounts,
    /// `0` (terrible) to `100` (perfect).
    pub score: u8,
    /// All findings, most severe first.
    pub findings: Vec<Finding>,
    /// How many passwords were checked against the breach corpus.
    pub breaches_checked: usize,
}

impl AuditReport {
    /// Findings of one kind.
    pub fn of_kind(&self, kind: FindingKind) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.kind == kind)
    }

    /// A single word describing the score.
    pub fn verdict(&self) -> &'static str {
        match self.score {
            90..=100 => "Excellent",
            75..=89 => "Good",
            50..=74 => "Needs work",
            25..=49 => "Poor",
            _ => "Critical",
        }
    }
}

/// Options controlling what the audit looks at.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditOptions {
    /// Flag passwords scoring below this (0–4).
    pub weak_threshold: u8,
    /// Flag passwords older than this many days.
    pub stale_days: i64,
    /// Report logins without TOTP.
    pub report_missing_totp: bool,
    /// Report items that were never used.
    pub report_unused: bool,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            weak_threshold: 2,
            stale_days: 730,
            report_missing_totp: true,
            report_unused: false,
        }
    }
}

/// Run the audit.
///
/// `breaches` maps item id → number of times the password appeared in known
/// breaches; pass an empty map when the user has breach checking disabled.
pub fn audit(
    data: &VaultData,
    breaches: &HashMap<Uuid, u32>,
    options: &AuditOptions,
    now: DateTime<Utc>,
) -> AuditReport {
    let mut findings = Vec::new();
    let mut counts = HealthCounts::default();

    let items: Vec<&crate::model::Item> = data.active().collect();
    counts.items = items.len();

    // --- weak passwords -------------------------------------------------
    for item in &items {
        let Some(password) = item.password() else {
            if item.kind.has_auditable_password() {
                findings.push(Finding {
                    kind: FindingKind::EmptyPassword,
                    severity: Severity::Medium,
                    item_id: Some(item.id),
                    item_title: item.title.clone(),
                    detail: "This entry has no password stored.".into(),
                    remediation: "Generate a password and save it to the vault.".into(),
                });
            }
            continue;
        };
        counts.passwords += 1;
        let user_inputs: Vec<&str> = [item.title.as_str()]
            .into_iter()
            .chain(item.username.as_deref())
            .collect();
        let s = strength::evaluate(password, &user_inputs);
        if s.score <= options.weak_threshold {
            counts.weak += 1;
            findings.push(Finding {
                kind: FindingKind::WeakPassword,
                severity: if s.score == 0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                item_id: Some(item.id),
                item_title: item.title.clone(),
                detail: format!(
                    "Rated “{}” ({}). {}",
                    s.label,
                    s.crack_time,
                    s.warning.clone().unwrap_or_default()
                )
                .trim()
                .to_string(),
                remediation: "Replace it with a generated password of 16+ characters.".into(),
            });
        }

        if let Some(changed) = item.password_changed_at.or(Some(item.updated_at)) {
            let age = now.signed_duration_since(changed).num_days();
            if age > options.stale_days {
                counts.stale += 1;
                findings.push(Finding {
                    kind: FindingKind::StalePassword,
                    severity: Severity::Low,
                    item_id: Some(item.id),
                    item_title: item.title.clone(),
                    detail: format!("The password has not changed in {age} days."),
                    remediation: "Rotate it — especially for anything exposed to the internet."
                        .into(),
                });
            }
        }
    }

    // --- reused passwords ----------------------------------------------
    for (password, ids) in data.reused_passwords() {
        counts.reused += ids.len();
        let titles: Vec<String> = ids
            .iter()
            .filter_map(|id| data.get(*id).map(|i| i.title.clone()))
            .collect();
        findings.push(Finding {
            kind: FindingKind::ReusedPassword,
            severity: Severity::High,
            item_id: ids.first().copied(),
            item_title: titles.join(", "),
            detail: format!(
                "{} entries share the same password ({}). One leak compromises them all.",
                ids.len(),
                crate::util::truncate(&password, 1)
            ),
            remediation: "Give every account its own generated password.".into(),
        });
    }

    // --- breached passwords --------------------------------------------
    for item in &items {
        if let Some(count) = breaches.get(&item.id).filter(|c| **c > 0) {
            counts.breached += 1;
            findings.push(Finding {
                kind: FindingKind::BreachedPassword,
                severity: Severity::Critical,
                item_id: Some(item.id),
                item_title: item.title.clone(),
                detail: format!(
                    "This password appears {count} times in known data breaches. It is public."
                ),
                remediation: "Change it everywhere it is used, starting here.".into(),
            });
        }
    }
    counts.breached = items
        .iter()
        .filter(|i| breaches.get(&i.id).is_some_and(|c| *c > 0))
        .count();

    // --- expiry ---------------------------------------------------------
    for item in &items {
        if item.is_expired(now) {
            counts.expired += 1;
            findings.push(Finding {
                kind: FindingKind::Expired,
                severity: Severity::Medium,
                item_id: Some(item.id),
                item_title: item.title.clone(),
                detail: format!(
                    "Expired on {}.",
                    item.expires_at
                        .map(|t| t.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "an unknown date".into())
                ),
                remediation: "Renew it or delete the entry.".into(),
            });
        }
    }

    // --- missing two-factor --------------------------------------------
    if options.report_missing_totp {
        for item in &items {
            if item.kind == ItemKind::Login && item.totp.is_none() && item.password().is_some() {
                counts.missing_totp += 1;
                findings.push(Finding {
                    kind: FindingKind::MissingTotp,
                    severity: Severity::Low,
                    item_id: Some(item.id),
                    item_title: item.title.clone(),
                    detail: "No one-time-password secret is stored for this login.".into(),
                    remediation:
                        "Enable two-factor authentication on the site and add the secret here."
                            .into(),
                });
            }
        }
    }

    // --- duplicates -----------------------------------------------------
    let groups = data.duplicate_groups();
    counts.duplicates = groups.len();
    for group in groups {
        let titles: Vec<String> = group
            .iter()
            .filter_map(|id| data.get(*id).map(|i| i.title.clone()))
            .collect();
        findings.push(Finding {
            kind: FindingKind::Duplicate,
            severity: Severity::Low,
            item_id: group.first().copied(),
            item_title: titles.join(", "),
            detail: format!("{} entries look like the same account.", group.len()),
            remediation: "Merge them so you always update the right one.".into(),
        });
    }

    // --- never used -----------------------------------------------------
    if options.report_unused {
        for item in &items {
            if item.last_used_at.is_none()
                && now.signed_duration_since(item.created_at).num_days() > 180
            {
                findings.push(Finding {
                    kind: FindingKind::Unused,
                    severity: Severity::Info,
                    item_id: Some(item.id),
                    item_title: item.title.clone(),
                    detail: "This entry has never been used or copied.".into(),
                    remediation: "Delete it if the account no longer exists.".into(),
                });
            }
        }
    }

    // Most severe first, then by title so the order is stable.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.item_title.to_lowercase().cmp(&b.item_title.to_lowercase()))
            .then_with(|| format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
    });

    let penalty: i32 = findings.iter().map(|f| f.severity.penalty()).sum();
    let score = (100 - penalty).clamp(0, 100) as u8;

    AuditReport {
        generated_at: now,
        counts: HealthCounts {
            breached: counts.breached,
            ..counts
        },
        score,
        findings,
        breaches_checked: breaches.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attachment, Field, PasswordHistoryEntry, VaultSettings};

    fn item(title: &str, password: Option<&str>, kind: ItemKind) -> crate::model::Item {
        let mut i = crate::model::Item::new(kind, title);
        i.password = password.map(|p| p.to_string());
        i.password_changed_at = Some(Utc::now());
        i
    }

    fn data_with(items: Vec<crate::model::Item>) -> VaultData {
        // Construct explicitly so the test does not depend on Default for new
        // fields being added later.
        let _ = (
            Attachment {
                id: Uuid::nil(),
                name: String::new(),
                mime: String::new(),
                size: 0,
                data: String::new(),
                created_at: Utc::now(),
            },
            Field::new("a", "b"),
            PasswordHistoryEntry {
                password: "x".into(),
                changed_at: Utc::now(),
            },
            VaultSettings::default(),
        );
        VaultData {
            items,
            ..Default::default()
        }
    }

    #[test]
    fn a_clean_vault_scores_perfectly() {
        let data = data_with(vec![item(
            "Bank",
            Some("kR7#pQ2!vLm9@xZ4wN8^"),
            ItemKind::Login,
        )]);
        // Give it a TOTP so the missing-2FA rule does not fire.
        let mut data = data;
        data.items[0].totp = Some("JBSWY3DPEHPK3PXP".into());
        let report = audit(&data, &HashMap::new(), &AuditOptions::default(), Utc::now());
        assert_eq!(report.score, 100, "{:#?}", report.findings);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn weak_and_reused_passwords_are_flagged() {
        let data = data_with(vec![
            item("A", Some("password"), ItemKind::Login),
            item("B", Some("password"), ItemKind::Login),
        ]);
        let report = audit(&data, &HashMap::new(), &AuditOptions::default(), Utc::now());
        assert_eq!(report.counts.weak, 2);
        assert_eq!(report.findings.iter().filter(|f| f.kind == FindingKind::ReusedPassword).count(), 1);
        assert!(report.score < 100);
    }

    #[test]
    fn breached_passwords_are_critical_and_dominate() {
        let data = data_with(vec![item("A", Some("Str0ng!Passw0rd#2026"), ItemKind::Login)]);
        let id = data.items[0].id;
        let mut breaches = HashMap::new();
        breaches.insert(id, 4200);
        let report = audit(&data, &breaches, &AuditOptions::default(), Utc::now());
        assert_eq!(report.counts.breached, 1);
        let first = report.findings.first().unwrap();
        assert_eq!(first.kind, FindingKind::BreachedPassword);
        assert_eq!(first.severity, Severity::Critical);
        // Breach + no 2FA.
        assert_eq!(report.score, 100 - 15 - 1);
    }

    #[test]
    fn missing_password_is_reported_for_logins() {
        let data = data_with(vec![item("A", None, ItemKind::Login)]);
        let report = audit(&data, &HashMap::new(), &AuditOptions::default(), Utc::now());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::EmptyPassword));
    }

    #[test]
    fn stale_passwords_use_the_configured_age() {
        let mut d = data_with(vec![item("A", Some("kR7#pQ2!vLm9@xZ4wN8^"), ItemKind::Login)]);
        d.items[0].totp = Some("JBSWY3DPEHPK3PXP".into());
        d.items[0].password_changed_at = Some(Utc::now() - chrono::Duration::days(3000));
        let report = audit(&d, &HashMap::new(), &AuditOptions::default(), Utc::now());
        assert!(report.findings.iter().any(|f| f.kind == FindingKind::StalePassword));
    }
}
