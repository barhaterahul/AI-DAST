// UI strings for the AI-DAST-ING dashboard (English only).
//
// Keys are dot-namespaced by surface (nav.*, topbar.*, common.*) so the map
// stays browsable. The t() helper falls back to the raw key when a string is
// missing, so a missing entry degrades gracefully instead of rendering blank.

type Dict = Record<string, string>;

const en: Dict = {
  // Sidebar navigation
  "nav.overview": "Overview",
  "nav.newScan": "New Scan",
  "nav.scans": "Scans",
  "nav.schedules": "Schedules",
  "nav.exploration": "Exploration Graph",
  "nav.findings": "Findings",
  "nav.live": "Live Feed",
  "nav.reports": "Reports",
  "nav.integrations": "Integrations",
  "nav.tokenProviders": "Token Providers",
  "nav.settings": "Settings",
  "sidebar.localScanner": "Local scanner",
  "sidebar.commandHint": "Ctrl+K for actions",
  "sidebar.navigation": "Main navigation",

  // Topbar
  "topbar.searchLong": "Search scans, findings, actions…",
  "topbar.searchShort": "Search…",
  "topbar.openPalette": "Open command palette",
  "topbar.toggleMenu": "Toggle menu",
  "topbar.newScan": "New Scan",
  "topbar.signOut": "Sign out",
  "topbar.stopAll": "Stop all",
  "topbar.scanning": "Scanning",
  "topbar.activeScan": "active scan",
  "topbar.activeScans": "active scans",
  "topbar.language": "Language",
  "topbar.theme": "Theme",
  "theme.light": "Light",
  "theme.dark": "Dark",
  "theme.system": "System",

  // Severity labels (shared across findings, badges, tables)
  "severity.critical": "Critical",
  "severity.high": "High",
  "severity.medium": "Medium",
  "severity.low": "Low",
  "severity.info": "Info",

  // Scan status labels (shared across scans, instances, pills)
  "status.running": "Running",
  "status.pending": "Pending",
  "status.paused": "Paused",
  "status.saved": "Saved",
  "status.completed": "Completed",
  "status.finished": "Completed",
  "status.stopped": "Stopped",
  "status.failed": "Failed",
  "status.unknown": "Unknown",

  // Common
  "common.loading": "Loading…",
  "common.save": "Save",
  "common.cancel": "Cancel",
  "common.open": "Open",
  "common.delete": "Delete",
  "common.somethingWrong": "Something went wrong",
  "common.findings": "findings",
  "common.tokens": "tokens",

  // States
  "states.noData": "No data",

  // Reports page
  "reports.title": "Reports",
  "reports.subtitle": "PDF reports for every completed scan. Generated on demand by the server.",
  "reports.searchPlaceholder": "Search reports by target or scan ID…",
  "reports.emptyTitle": "No reports yet",
  "reports.emptyDescription": "Run a scan and a PDF report will be available here.",
  "reports.confirmDelete": "Permanently delete this report and scan record?",

  // Overview page
  "overview.title": "Overview",
  "overview.recentScans": "Recent Scans",
  "overview.liveActivity": "Live Activity",
  "overview.systemHealth": "System Health",
  "overview.criticalFindings": "Critical Findings",
  "overview.findingMix": "Finding Mix",
  "overview.operations": "Operations",
  "overview.latestScan": "Latest scan",

  // Findings page
  "findings.title": "Findings",
  "findings.allSeverities": "All severities",

  // Scans page
  "scans.title": "Scans",
  "scans.subtitle": "All historical and in-flight scans.",
  "scans.allStatuses": "All statuses",
  "scans.col.findings": "Findings",
  "scans.col.tokens": "Tokens",
  "scans.col.started": "Started",
  "scans.col.status": "Status",
  "scans.col.actions": "Actions",

  // New Scan page
  "newScan.back": "Back",
  "newScan.heading": "Start a new scan",
  "newScan.section.targets": "Targets",
  "newScan.label.targets": "Targets *",
  "newScan.label.targetsOptional": "Targets (optional)",
  "newScan.label.displayName": "Display name (optional)",
  "newScan.section.securityContext": "Security context (optional)",
  "newScan.section.apiCollection": "API collection (optional)",
  "newScan.section.authAccess": "Authenticated access (optional)",
  "newScan.label.authSession": "Authenticated session",
  "newScan.label.secondAccount": "Second account (for IDOR/BOLA proof)",
  "newScan.section.targetAccess": "Target access",
  "newScan.section.reportBranding": "Report branding",
  "newScan.label.brandName": "Target brand name",
  "newScan.label.brandLogo": "Target brand logo",
  "newScan.section.scanMode": "Scan mode",
  "newScan.section.refinement": "Refinement",
  "newScan.label.severityFilter": "Severity filter",
  "newScan.label.customInstruction": "Custom instruction",
  "newScan.label.modelOverride": "Model override",
  "newScan.label.providerProfile": "Provider profile",
  "newScan.btn.saveForLater": "Save for later",
  "newScan.btn.startScan": "Start scan",

  // Schedules page
  "schedules.title": "Schedules",
  "schedules.subtitle": "Manage automated recurring scans running on configured intervals.",
  "schedules.new": "New schedule",
  "schedules.create": "Create schedule",
  "schedules.emptyTitle": "No scheduled scans",
  "schedules.emptyDescription": "Automate recurring testing across your target landscape.",
  "schedules.never": "Never",
  "schedules.label.name": "Schedule Name *",
  "schedules.label.interval": "Frequency Interval *",
  "schedules.label.runAt": "Run at",
  "schedules.label.timezone": "Timezone",
  "schedules.label.targets": "Targets *",
  "schedules.label.scanMode": "Scan Mode",
  "schedules.label.providerProfile": "Provider profile",
  "schedules.label.reconAccess": "Recon Access",
  "schedules.label.testingAccess": "Testing Access",
  "schedules.label.modelOverride": "Model override",
  "schedules.label.severityFilter": "Severity filter",
  "schedules.label.companyName": "Branding Company Name",
  "schedules.label.brandLogo": "Target Brand Logo",
  "schedules.saving": "Saving…",
  "schedules.saveSchedule": "Save schedule",
  "schedules.runNow": "Run now",
  "schedules.editSettings": "Edit settings",
  "schedules.deleteSchedule": "Delete schedule",

  // Instances page
  "exploration.title": "Exploration Graph",
  "exploration.subtitle": "How each finding was found — from discovery to injection to proof.",

  // Integrations page
  "integrations.title": "Integrations",
  "integrations.category.AI": "AI",
  "integrations.category.Engagement": "Engagement",
  "integrations.connected": "Connected",
  "integrations.notConnected": "Not connected",

  // Live page
  "live.title": "Live Feed",


  // Scan detail page
  "scanDetail.phaseProgress": "Phase progress",
  "scanDetail.riskOverview": "Risk overview",
  "scanDetail.wildcardCoverage": "Wildcard coverage",
  "scanDetail.tab.tokens": "Token usage",
  // Token usage tab
  "scanDetail.token.total": "Total token usage",
  "scanDetail.token.requests": "LLM requests",
  "scanDetail.token.agents": "Token usage by agent",
  "scanDetail.token.context": "Context growth",
  "scanDetail.token.contextHint": "Prompt tokens per LLM request over the scan. A steadily rising line is accumulated conversation history being resent on every iteration.",
  "scanDetail.token.sources": "Active context composition",
  "scanDetail.token.sourcesHint": "Approximate composition of each agent's most recent outbound request.",
  "scanDetail.token.recovery": "Recovery loops",
  "scanDetail.token.loading": "Loading token usage…",
  "scanDetail.token.unavailable": "Token usage data is not available for this scan.",
  "scanDetail.tab.findings": "Findings",
  "scanDetail.tab.events": "Events",
  "scanDetail.tab.subdomains": "Subdomains",
  "scanDetail.tab.config": "Config",
  "scanDetail.guideScan": "Guide this scan",

  // Settings page
  "settings.title": "Settings",
  "settings.tab.llm": "LLM",
  "settings.tab.engagement": "Engagement",
  "settings.tab.environment": "Environment",
  "settings.backup.title": "Backup & migration",
  "settings.backup.desc":
    "Export the full configuration (environment variables, LLM profiles, provider keys) to a file, or import a previous backup into this install. Import merges — values not in the file are left untouched.",
  "settings.backup.export": "Export configuration",
  "settings.backup.import": "Import configuration",
  "settings.backup.confirm": "Import this backup into this scanner?",
  "settings.tab.account": "Account",
  "settings.card.llmProvider": "LLM provider",
  "settings.card.rateLimits": "Rate limits",
  "settings.card.account": "Account",
  "settings.account.desc": "Session and access.",
  "settings.savedIndicator": "Saved",
  "settings.searchVariables": "Search variables...",
};

export const translations: Dict = en;
