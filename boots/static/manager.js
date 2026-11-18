const BRA_AUTH_COOKIE = "bra_gui_session";

function getBraCookie(name) {
    const prefix = `${name}=`;
    for (const part of document.cookie.split(";")) {
        const trimmed = part.trim();
        if (trimmed.startsWith(prefix)) {
            return decodeURIComponent(trimmed.slice(prefix.length));
        }
    }
    return "";
}

function braAuthCookieAttrs() {
    const attrs = ["Path=/", "SameSite=Strict"];
    if (window.location.protocol === "https:") attrs.push("Secure");
    return attrs.join("; ");
}

function persistBraAuthToken(rawToken) {
    const token = String(rawToken || "").trim();
    if (token) {
        localStorage.setItem("bra-gui-token", token);
        document.cookie = `${BRA_AUTH_COOKIE}=${encodeURIComponent(token)}; Max-Age=2592000; ${braAuthCookieAttrs()}`;
    } else {
        localStorage.removeItem("bra-gui-token");
        document.cookie = `${BRA_AUTH_COOKIE}=; Max-Age=0; ${braAuthCookieAttrs()}`;
    }
    return token;
}

function stripBraTokenFromUrl() {
    const url = new URL(window.location.href);
    if (!url.searchParams.has("token")) return;
    url.searchParams.delete("token");
    const next = `${url.pathname}${url.searchParams.toString() ? `?${url.searchParams.toString()}` : ""}${url.hash}`;
    window.history.replaceState({}, document.title, next);
}

function getBraInitialToken() {
    const params = new URLSearchParams(window.location.search);
    const fromUrl = String(params.get("token") || "").trim();
    const fromStorage = String(localStorage.getItem("bra-gui-token") || "").trim();
    const fromCookie = String(getBraCookie(BRA_AUTH_COOKIE) || "").trim();
    const token = fromUrl || fromStorage || fromCookie || "";
    if (token) persistBraAuthToken(token);
    if (fromUrl) stripBraTokenFromUrl();
    return token;
}

function managerApp() {
    return {
        token: "",
        tokenInput: "",
        loading: false,
        error: "",
        cards: [],
        selectedId: "current-bra",
        selected: {},
        actionQueue: [],
        kpis: {
            active_engagements: 0,
            critical_high: 0,
            pending_decisions: 0,
            readiness_avg: 0,
        },
        liveFallbacks: { current_bra: {} },
        live: {
            engagement: {},
            findings: {},
            leads: {},
            summary: {},
            governance: {},
            telemetry: {},
            report: {},
        },

        async init() {
            this.token = getBraInitialToken();
            this.tokenInput = this.token;
            await this.loadAll();
        },

        saveToken() {
            const next = (this.tokenInput || "").trim();
            if (!next) return;
            this.token = persistBraAuthToken(next);
            stripBraTokenFromUrl();
            this.loadAll();
        },

        async api(endpoint) {
            const headers = {};
            if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
            const resp = await fetch(`/api${endpoint}`, { headers });
            if (!resp.ok) {
                throw new Error(`API ${endpoint} failed (${resp.status})`);
            }
            return resp.json();
        },

        async loadAll() {
            this.error = "";
            this.loading = true;
            try {
                const [portfolio, engagement, findings, leads, summary, governance, telemetry, report] = await Promise.all([
                    this.api("/manager/portfolio"),
                    this.api("/engagement"),
                    this.api("/findings"),
                    this.api("/leads"),
                    this.api("/summary"),
                    this.api("/governance"),
                    this.api("/telemetry"),
                    this.api("/report"),
                ]);
                this.liveFallbacks = portfolio.live_fallbacks || { current_bra: {} };
                this.live = { engagement, findings, leads, summary, governance, telemetry, report };
                this.buildCards(portfolio.engagements || []);
            } catch (err) {
                this.error = String(err.message || err);
                this.buildCards([]);
            } finally {
                this.loading = false;
            }
        },

        buildCards(mockEngagements) {
            const current = this.buildCurrentBraCard();
            const peers = Array.isArray(mockEngagements) ? mockEngagements.slice(0, 3) : [];
            this.cards = [current, ...peers];
            if (!this.cards.some((c) => c.id === this.selectedId)) {
                this.selectedId = this.cards[0]?.id || "current-bra";
            }
            this.selected = this.cards.find((c) => c.id === this.selectedId) || current;
            this.buildKpis();
            this.buildActionQueue();
        },

        buildCurrentBraCard() {
            const fallback = (this.liveFallbacks.current_bra || {});
            const stats = ((this.live.summary || {}).parsed || {}).finding_statistics || {};
            const critical = Number(stats.CRITICAL || 0);
            const high = Number(stats.HIGH || 0);
            const criticalHigh = critical + high;

            const coverageGaps = Number((((this.live.summary || {}).parsed || {}).coverage_gaps || {}).gap_count || 0);
            const pendingFindings = Number((this.live.findings || {}).pending_count || 0);
            const leads = (((this.live.leads || {}).parsed || {}).leads || []);
            const openLeads = leads.filter((lead) => String(lead.status || "").toLowerCase() !== "closed").length;
            const status = (this.live.engagement || {}).status || "Inactive";

            let riskLevel = String(fallback.risk_level || "MEDIUM").toUpperCase();
            if ((this.live.governance || {}).kill_switch === "STOP") riskLevel = "CRITICAL";
            else if (criticalHigh > 0) riskLevel = "HIGH";
            else if (pendingFindings > 0 || coverageGaps > 0) riskLevel = "MEDIUM";
            else riskLevel = "LOW";

            const reportReadinessLive = this.estimateReportReadiness();
            const telemetryScoreLive = this.estimateTelemetryScore();

            return {
                id: "current-bra",
                name: "CURRENT BRA",
                status: status,
                risk_level: riskLevel,
                critical_high: criticalHigh,
                pending_decisions: pendingFindings,
                pending_findings: pendingFindings,
                open_leads: openLeads,
                coverage_gaps: coverageGaps,
                report_readiness: reportReadinessLive ?? Number(fallback.report_readiness || 0),
                telemetry_score: telemetryScoreLive ?? Number(fallback.telemetry_score || 0),
                kill_switch: (this.live.governance || {}).kill_switch || "UNKNOWN",
                manager_note: fallback.manager_note || "",
                last_update: new Date().toISOString(),
            };
        },

        estimateReportReadiness() {
            const report = this.live.report || {};
            if (report.exists && report.engagement_report && report.engagement_report.has_content) return 85;
            if ((this.live.summary || {}).exists) return 60;
            if ((this.live.findings || {}).count > 0) return 45;
            return null;
        },

        estimateTelemetryScore() {
            const telemetry = this.live.telemetry || {};
            const level = Number((((telemetry || {}).battle_card || {}).level) || 0);
            if (!level) return null;
            return Math.max(1, Math.min(99, level));
        },

        buildKpis() {
            const cards = this.cards || [];
            const active = cards.filter((c) => String(c.status || "").toLowerCase() === "active").length;
            const criticalHigh = cards.reduce((sum, c) => sum + Number(c.critical_high || 0), 0);
            const pending = cards.reduce((sum, c) => sum + Number(c.pending_decisions || 0), 0);
            const avg = cards.length
                ? Math.round(cards.reduce((sum, c) => sum + Number(c.report_readiness || 0), 0) / cards.length)
                : 0;
            this.kpis = {
                active_engagements: active,
                critical_high: criticalHigh,
                pending_decisions: pending,
                readiness_avg: avg,
            };
        },

        buildActionQueue() {
            const selected = this.selected || {};
            const queue = [];
            if (String(selected.risk_level || "").toUpperCase() === "CRITICAL") {
                queue.push("Escalate kill-switch or critical risk posture review.");
            }
            if (Number(selected.pending_findings || 0) > 0) {
                queue.push(`Review pending findings queue (${selected.pending_findings}).`);
            }
            if (Number(selected.coverage_gaps || 0) > 0) {
                queue.push(`Close ${selected.coverage_gaps} coverage gap(s) before report freeze.`);
            }
            if (Number(selected.report_readiness || 0) < 60) {
                queue.push("Increase report readiness before stakeholder handoff.");
            }
            if (selected.manager_note) {
                queue.push(`Note: ${selected.manager_note}`);
            }
            this.actionQueue = queue;
        },

        selectCard(cardId) {
            this.selectedId = cardId;
            this.selected = this.cards.find((c) => c.id === cardId) || {};
            this.buildActionQueue();
        },

        formatTime(iso) {
            if (!iso) return "-";
            const dt = new Date(iso);
            if (Number.isNaN(dt.getTime())) return iso;
            return dt.toLocaleString();
        },

        riskClass(level) {
            const norm = String(level || "").toLowerCase();
            if (norm === "critical") return "risk-critical";
            if (norm === "high") return "risk-high";
            if (norm === "medium") return "risk-medium";
            return "risk-low";
        },

        backUrl() {
            return "/#dashboard";
        },
    };
}

// Alpine expressions evaluate against window scope; expose the factory explicitly.
window.managerApp = managerApp;
