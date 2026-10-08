-- Leviathan Intel - core schema (PostgreSQL 16)
-- Defensive attack-surface management: tenants (customers), THEIR assets,
-- CVE intel, PoC references, correlated findings.

CREATE TABLE IF NOT EXISTS tenants (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(120) UNIQUE NOT NULL,
    plan        VARCHAR(30) NOT NULL DEFAULT 'trial',
    api_token   VARCHAR(80) UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Assets are ONLY the domains/IPs a tenant registered with us (authorized scope).
CREATE TABLE IF NOT EXISTS assets (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        VARCHAR(20) NOT NULL CHECK (kind IN ('domain','ip','service')),
    value       VARCHAR(255) NOT NULL,          -- domain name, IP, or ip:port
    ip          INET,
    port        INTEGER,
    banner      TEXT,
    cpe         VARCHAR(255),                   -- cpe:2.3:a:vendor:product:version
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_cpe ON assets(cpe) WHERE cpe IS NOT NULL;

-- CVE intel: NVD + EPSS + CISA KEV merged into one row per CVE.
CREATE TABLE IF NOT EXISTS cves (
    cve_id        VARCHAR(20) PRIMARY KEY,
    description   TEXT,
    remediation   TEXT,                         -- plain-language fix suggestion (CVEDB)
    cvss          NUMERIC(3,1),
    severity      VARCHAR(12),
    epss          NUMERIC(6,5),                 -- FIRST EPSS probability 0-1
    epss_date     DATE,
    kev           BOOLEAN NOT NULL DEFAULT FALSE,   -- in CISA Known Exploited Vulns
    kev_date      DATE,
    cpe_matches   JSONB,                        -- NVD configurations -> CPE strings
    published     TIMESTAMPTZ,
    modified      TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev) WHERE kev;
CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss DESC NULLS LAST);

-- Public PoC references (Sploitus / Exploit-DB / NVD references).
CREATE TABLE IF NOT EXISTS poc_refs (
    id        SERIAL PRIMARY KEY,
    cve_id    VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    source    VARCHAR(20) NOT NULL CHECK (source IN ('sploitus','exploitdb','nvd','github')),
    url       TEXT NOT NULL,
    found_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, source, url)
);
CREATE INDEX IF NOT EXISTS idx_poc_cve ON poc_refs(cve_id);

-- The correlation output: a finding = (tenant asset, CVE, explainable priority).
CREATE TABLE IF NOT EXISTS findings (
    id          SERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id      VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    priority    SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 100),
    reasons     JSONB NOT NULL DEFAULT '[]',    -- explainable scoring, item by item
    status      VARCHAR(12) NOT NULL DEFAULT 'open'
                CHECK (status IN ('open','triaged','remediated','accepted')),
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_prio
    ON findings(asset_id, priority DESC);

-- Scan job bookkeeping (delta scanning: only deep-scan on asset change).
CREATE TABLE IF NOT EXISTS scan_jobs (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        VARCHAR(20) NOT NULL,           -- shodan_sync / nuclei_deep / dns_delta
    status      VARCHAR(12) NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','done','failed')),
    stats       JSONB NOT NULL DEFAULT '{}',
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

-- Beta billing: manually-reconciled crypto invoices (USDT-TON / TON / BTC).
-- The operator confirms arrival on their own receive wallet; marking an
-- invoice paid atomically promotes the tenant's plan. Custodial PSP rails
-- (Wallet Pay etc.) are deliberately avoided at this stage.
CREATE TABLE IF NOT EXISTS invoices (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    plan        VARCHAR(30) NOT NULL CHECK (plan IN ('trial','starter','pro')),
    amount_usd  NUMERIC(10,2) NOT NULL CHECK (amount_usd >= 0),
    currency    VARCHAR(12) NOT NULL,
    address     TEXT NOT NULL,
    memo        VARCHAR(20) UNIQUE NOT NULL,    -- LVTI-XXXXXX transfer reference
    status      VARCHAR(12) NOT NULL DEFAULT 'waiting'
                CHECK (status IN ('waiting','paid','expired','cancelled')),
    tx_ref      TEXT,                           -- operator-entered tx id / note
    expires_at  TIMESTAMPTZ NOT NULL,
    paid_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_invoices_tenant ON invoices(tenant_id);

-- Wallet Pay auto-settle columns (optional path; manual reconcile stays default).
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS wallet_order_id TEXT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS pay_link TEXT;
CREATE INDEX IF NOT EXISTS idx_invoices_wallet ON invoices(wallet_order_id)
    WHERE wallet_order_id IS NOT NULL;
