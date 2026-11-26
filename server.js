import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { GoogleGenAI, ThinkingLevel, Type } from "@google/genai";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const PUBLIC_DIR = path.join(__dirname, "public");
const SITE_DIR = path.join(__dirname, "site");
const D3_BUNDLE = path.join(__dirname, "node_modules", "d3", "dist", "d3.min.js");

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const KEV_URLS = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
];
const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/i;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".xml": "application/atom+xml; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

const SEV_FR = {
  CRITICAL: "CRITIQUE",
  HIGH: "ÉLEVÉE",
  MEDIUM: "MOYENNE",
  LOW: "FAIBLE",
  NONE: "AUCUNE",
};

const GLOSSAIRE = [
  { terme: "Vulnérabilité (faille)", def: "Une erreur dans un logiciel ou un équipement qu'un pirate peut utiliser pour l'attaquer. On la corrige en installant la mise à jour (le « correctif ») de l'éditeur." },
  { terme: "CVE", def: "Le numéro d'identification unique d'une faille, comme une plaque d'immatriculation (ex. CVE-2024-3400). Tout le monde utilise ce numéro pour parler de la même faille." },
  { terme: "Priorité P1 à P4", def: "Le niveau d'urgence calculé par VulnWatch pour TON contexte. P1 = urgent (48 h), P2 = cette semaine, P3 = dans le mois, P4 = rester informé." },
  { terme: "Gravité (CVSS)", def: "Note de 0 à 10 qui mesure les dégâts possibles si la faille est utilisée. 9 à 10 = très grave. Elle ne dit pas si des pirates l'utilisent vraiment : c'est le rôle de KEV et EPSS." },
  { terme: "Exploitée (KEV)", def: "La faille figure sur la liste officielle de l'agence américaine de cybersécurité (CISA) des failles déjà utilisées par des pirates. C'est le signal d'alarme le plus fort." },
  { terme: "EPSS", def: "La probabilité, en %, que la faille soit utilisée par des pirates dans les 30 prochains jours. La plupart des failles sont sous 1 % ; au-dessus de 10 %, c'est préoccupant." },
  { terme: "Exploit / Metasploit / PoC", def: "Un « exploit » est un programme qui utilise la faille. Une « preuve de concept » (PoC) montre que c'est possible ; un module Metasploit est une arme prête à l'emploi." },
  { terme: "SSVC", def: "L'avis de la CISA sur chaque faille : est-elle exploitée (Active), du code d'attaque existe-t-il (PoC), l'attaque peut-elle être automatisée, l'impact est-il total." },
  { terme: "Périmétrique", def: "Les équipements à l'entrée du réseau (VPN, pare-feu, passerelles). Ce sont les cibles préférées des pirates car ils sont exposés à Internet." },
  { terme: "Inventaire / Mon parc", def: "La liste de tes équipements et logiciels. Grâce à elle, VulnWatch sait quelles failles te concernent vraiment et augmente leur priorité." },
];

const EXPERT_VIEWS = [
  { name: "Exploitées activement", desc: "Au catalogue CISA KEV ou SSVC « Exploitation : Active »" },
  { name: "Rançongiciels", desc: "Failles utilisées dans des campagnes de rançongiciel (CISA)" },
  { name: "Échéance CISA ≤ 7 j", desc: "Failles KEV dont l'échéance de correction CISA est dépassée ou dans moins de 7 jours" },
  { name: "Périmétrique", desc: "VPN, pare-feu, passerelles, équilibreurs : la porte d'entrée favorite des attaquants" },
  { name: "Microsoft", desc: "Produits Microsoft (Windows, Exchange, Office, Edge…) — utile au Patch Tuesday" },
  { name: "Navigateurs", desc: "Chrome, Firefox, Safari, Edge, moteurs JavaScript" },
  { name: "Virtualisation / Cloud", desc: "Hyperviseurs, vCenter, conteneurs, Kubernetes, cloud" },
];

const PERIMETER_RE = /forti|palo alto|pan-os|citrix|ivanti|pulse|f5|big-ip|sonicwall|cisco asa|checkpoint|juniper|vpn|firewall|gateway/i;
const BROWSER_RE = /chrome|firefox|safari|edge|chromium|webkit/i;
const VIRT_RE = /vmware|esxi|vcenter|kubernetes|docker|citrix hypervisor|proxmox|xen|openstack/i;

function detectFamily(vendor = "", product = "", desc = "") {
  const hay = `${vendor} ${product} ${desc}`;
  if (PERIMETER_RE.test(hay)) return "Périmétrique";
  if (BROWSER_RE.test(hay)) return "Navigateur";
  if (VIRT_RE.test(hay)) return "Virtualisation";
  if (/windows|linux|android|ios|macos|ubuntu|debian|rhel/i.test(hay)) return "Système d'exploitation";
  return "";
}

function buildViewsForRecord(r, nowMs) {
  const views = [];
  if (r.kev) views.push("Exploitées activement");
  if (r.ransomware === "Known") views.push("Rançongiciels");
  if (r.kev_due) {
    const dueMs = Date.parse(r.kev_due);
    if (!Number.isNaN(dueMs) && (dueMs - nowMs) / 86400000 <= 7) {
      views.push("Échéance CISA ≤ 7 j");
    }
  }
  if (r.family === "Périmétrique") views.push("Périmétrique");
  if (/microsoft/i.test(r.vendor || "")) views.push("Microsoft");
  if (r.family === "Navigateur") views.push("Navigateurs");
  if (r.family === "Virtualisation") views.push("Virtualisation / Cloud");
  return views.join("; ");
}

function safeHttpUrl(raw) {
  if (typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048) return "";
  try {
    const u = new URL(trimmed);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.toString();
  } catch {
    return "";
  }
}

const REF_TAG_MAP = {
  patch: "Patch",
  "vendor-advisory": "Vendor Advisory",
  "vendor advisory": "Vendor Advisory",
  mitigation: "Mitigation",
  exploit: "Exploit",
  "release-notes": "Release Notes",
  "release notes": "Release Notes",
  "third-party-advisory": "Third Party Advisory",
  "third party advisory": "Third Party Advisory",
  "us-government-resource": "US Government Resource",
  "us government resource": "US Government Resource",
  "government-resource": "US Government Resource",
  "issue-tracking": "Issue Tracking",
  "issue tracking": "Issue Tracking",
  "mailing-list": "Mailing List",
  "mailing list": "Mailing List",
  "technical-description": "Technical Description",
  "technical description": "Technical Description",
  "vdb-entry": "VDB Entry",
  "vdb entry": "VDB Entry",
  "broken-link": "Broken Link",
  "broken link": "Broken Link",
};

const REF_TAG_PRIO = {
  Patch: 0,
  "Vendor Advisory": 1,
  Mitigation: 2,
  Exploit: 3,
  "US Government Resource": 4,
  "Release Notes": 5,
  "Third Party Advisory": 6,
  "Technical Description": 7,
  "Issue Tracking": 8,
  "Mailing List": 9,
  "VDB Entry": 10,
};

function normalizeRefTags(tags) {
  if (!Array.isArray(tags)) return [];
  const out = [];
  for (const t of tags) {
    const raw = String(t || "").trim();
    if (!raw || raw.startsWith("x_refsource_") || raw.startsWith("x_transferred")) continue;
    const mapped = REF_TAG_MAP[raw.toLowerCase()] || raw;
    if (!out.includes(mapped)) out.push(mapped);
  }
  return out;
}

function mergeReferenceLists(...lists) {
  const byUrl = new Map();
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      const url = safeHttpUrl(typeof item === "string" ? item : item?.url);
      if (!url) continue;
      const key = url.replace(/\/+$/, "").toLowerCase();
      const tags = normalizeRefTags(item?.tags);
      const name = typeof item?.name === "string" ? item.name.trim().slice(0, 140) : "";
      const source = typeof item?.source === "string" ? item.source.trim().slice(0, 80) : "";
      const existing = byUrl.get(key);
      if (existing) {
        for (const t of tags) {
          if (!existing.tags.includes(t)) existing.tags.push(t);
        }
        if (!existing.name && name) existing.name = name;
        if (!existing.source && source) existing.source = source;
      } else {
        byUrl.set(key, { url, tags, name, source });
      }
    }
  }
  const rank = (ref) => {
    if (!ref.tags.length) return 50;
    if (ref.tags.includes("Broken Link")) return 99;
    return Math.min(...ref.tags.map((t) => (REF_TAG_PRIO[t] != null ? REF_TAG_PRIO[t] : 30)));
  };
  return Array.from(byUrl.values())
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, 45);
}

function extractCpeInfo(configs) {
  let vendor = "";
  let product = "";
  const affectedList = [];
  const versionRanges = [];
  for (const cfg of Array.isArray(configs) ? configs : []) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (m.vulnerable === false) continue;
        const parts = String(m.criteria || "").split(":");
        if (parts.length < 5) continue;
        const v = parts[3] && parts[3] !== "*" && parts[3] !== "-" ? parts[3].replace(/_/g, " ") : "";
        const p = parts[4] && parts[4] !== "*" && parts[4] !== "-" ? parts[4].replace(/_/g, " ") : "";
        const ver = parts[5] && parts[5] !== "*" && parts[5] !== "-" ? parts[5] : "";
        if (!vendor && v) vendor = v;
        if (!product && p) product = p;
        const label = [v, p].filter(Boolean).join(" ").trim();
        if (label && !affectedList.includes(label) && affectedList.length < 6) {
          affectedList.push(label);
        }
        let range = "";
        if (m.versionStartIncluding && m.versionEndExcluding) range = `>= ${m.versionStartIncluding}, < ${m.versionEndExcluding}`;
        else if (m.versionStartIncluding && m.versionEndIncluding) range = `>= ${m.versionStartIncluding}, <= ${m.versionEndIncluding}`;
        else if (m.versionEndExcluding) range = `< ${m.versionEndExcluding}`;
        else if (m.versionEndIncluding) range = `<= ${m.versionEndIncluding}`;
        else if (m.versionStartIncluding) range = `>= ${m.versionStartIncluding}`;
        else if (ver) range = ver;
        if (range) {
          const entry = p && affectedList.length > 1 ? `${p} ${range}` : range;
          if (!versionRanges.includes(entry) && versionRanges.length < 8) versionRanges.push(entry);
        }
      }
    }
  }
  return {
    vendor,
    product,
    affected: affectedList.join("; "),
    versions: versionRanges.join(", "),
  };
}

function applyKevToRecord(rec, k, nowMs) {
  if (!rec || !k) return rec;
  const ransomware = k.knownRansomwareCampaignUse === "Known" ? "Known" : "";
  rec.kev = true;
  rec.kev_due = k.dueDate || rec.kev_due || "";
  if (ransomware) rec.ransomware = ransomware;
  rec.ssvc_exploitation = "Active";
  rec.priority = "P1";
  rec.risk = Math.max(rec.risk || 0, ransomware ? 96 : rec.family === "Périmétrique" ? 93 : 88);
  if (!rec.vendor && k.vendorProject) rec.vendor = k.vendorProject;
  if (!rec.product && k.product) rec.product = k.product;
  if (!rec.affected && (k.vendorProject || k.product)) rec.affected = `${k.vendorProject || ""} ${k.product || ""}`.trim();
  rec.justification = ransomware
    ? "Exploitée activement (catalogue CISA KEV) et utilisée par des rançongiciels."
    : "Exploitée activement par des attaquants (catalogue officiel CISA KEV).";
  if (!rec.plain) {
    rec.plain = `Une faille dans ${rec.affected || rec.id} (${k.vulnerabilityName || rec.id}). ⚠️ Des pirates l'utilisent déjà dans de vraies attaques${ransomware ? ", y compris des groupes de rançongiciels" : ""}.`;
  }
  rec.todo = `URGENT — sous 48 h : ${k.requiredAction || "appliquer la mise à jour de sécurité de l'éditeur"}.${k.dueDate ? ` Échéance recommandée par la CISA : ${k.dueDate}.` : ""}`;
  rec.views = buildViewsForRecord(rec, nowMs);
  return rec;
}

function parseNvdCve(item, nowMs, cutoff1, kevMap = null) {
  const cve = item?.cve;
  if (!cve?.id) return null;

  const metrics = cve.metrics || {};
  const metricEntry =
    metrics.cvssMetricV31?.[0] ||
    metrics.cvssMetricV40?.[0] ||
    metrics.cvssMetricV30?.[0] ||
    metrics.cvssMetricV2?.[0];

  const cvssData = metricEntry?.cvssData || {};
  const score = typeof cvssData.baseScore === "number" ? cvssData.baseScore : null;
  const rawSev = (cvssData.baseSeverity || metricEntry?.baseSeverity || "").toUpperCase();
  const severity = SEV_FR[rawSev] || (score == null ? "NON ÉVALUÉE" : score >= 9 ? "CRITIQUE" : score >= 7 ? "ÉLEVÉE" : score >= 4 ? "MOYENNE" : "FAIBLE");
  const vector = cvssData.vectorString || "";

  const descs = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const desc = (descs.find((d) => d.lang === "fr") || descs.find((d) => d.lang === "en") || descs[0])?.value || "";

  const cpeInfo = extractCpeInfo(cve.configurations);
  const { vendor, product, versions } = cpeInfo;

  const cwes = [];
  for (const w of Array.isArray(cve.weaknesses) ? cve.weaknesses : []) {
    for (const d of w.description || []) {
      const val = String(d?.value || "").trim();
      if (/^CWE-\d+$/i.test(val) && !cwes.includes(val.toUpperCase())) {
        cwes.push(val.toUpperCase());
      }
    }
  }

  const references = mergeReferenceLists(Array.isArray(cve.references) ? cve.references : []);
  const patchRef =
    references.find((r) => r.tags.includes("Patch"))?.url ||
    references.find((r) => r.tags.includes("Vendor Advisory"))?.url ||
    references.find((r) => r.tags.includes("Mitigation"))?.url ||
    "";
  const exploitRef = references.find((r) => r.tags.includes("Exploit"))?.url || "";
  const hasExploitRef = Boolean(exploitRef);

  const published = cve.published ? `${cve.published.slice(0, 19)}Z` : "";
  const modified = cve.lastModified ? `${cve.lastModified.slice(0, 19)}Z` : published;
  const pubMs = Date.parse(published) || nowMs;
  const isNew = pubMs >= cutoff1;

  let priority = "P4";
  let justification = "Gravité modérée ou faible, sans exploitation publique recensée.";
  if (score != null && score >= 9.0 && hasExploitRef) {
    priority = "P1";
    justification = `Faille critique (${score.toFixed(1)}/10) avec preuve de concept publique référencée.`;
  } else if (score != null && score >= 9.0) {
    priority = "P2";
    justification = `Faille de gravité critique (${score.toFixed(1)}/10) à corriger cette semaine.`;
  } else if (score != null && score >= 7.0) {
    priority = hasExploitRef ? "P2" : "P3";
    justification = hasExploitRef
      ? `Gravité élevée (${score.toFixed(1)}/10) avec preuve de concept publique.`
      : `Gravité élevée (${score.toFixed(1)}/10), correction à planifier sous 30 jours.`;
  }

  const family = detectFamily(vendor, product, desc);
  const risk = score == null ? 20 : Math.min(95, Math.round(score * 8 + (hasExploitRef ? 12 : 0)));
  const affected = cpeInfo.affected || [vendor, product].filter(Boolean).join(" ").trim();

  const rec = {
    id: cve.id,
    priority,
    severity,
    score,
    score_source: metricEntry?.source ? (metricEntry.type === "Primary" ? "NVD" : "CNA") : "NVD",
    vector,
    risk,
    vendor,
    product,
    affected,
    versions,
    cwe: cwes.join(", "),
    family,
    desc,
    status: cve.vulnStatus || "",
    source: cve.sourceIdentifier || "",
    kev: false,
    exploit_maturity: hasExploitRef ? "Preuve de concept publique" : "",
    exploit_ref: exploitRef,
    patch_available: patchRef ? "Oui" : "",
    ref_patch: patchRef,
    references,
    new: isNew,
    published,
    modified,
    justification,
  };
  rec.views = buildViewsForRecord(rec, nowMs);
  if (kevMap && kevMap.has(rec.id)) {
    applyKevToRecord(rec, kevMap.get(rec.id), nowMs);
  }
  return rec;
}

function parseMitreCve5(payload, nowMs, cutoff1, kevMap = null) {
  const meta = payload?.cveMetadata;
  const cveId = meta?.cveId;
  if (!cveId) return null;
  const cna = payload?.containers?.cna || {};
  const adps = Array.isArray(payload?.containers?.adp) ? payload.containers.adp : [];

  const descs = Array.isArray(cna.descriptions) ? cna.descriptions : [];
  const desc = (descs.find((d) => /^fr/i.test(d.lang || "")) || descs.find((d) => /^en/i.test(d.lang || "")) || descs[0])?.value || cna.title || "";

  let vendor = "";
  let product = "";
  const affectedList = [];
  const versionList = [];
  const fixedList = [];
  for (const a of Array.isArray(cna.affected) ? cna.affected : []) {
    const v = String(a.vendor || "").trim();
    const p = String(a.product || "").trim();
    if (!vendor && v && v.toLowerCase() !== "n/a") vendor = v;
    if (!product && p && p.toLowerCase() !== "n/a") product = p;
    const lbl = [v !== "n/a" ? v : "", p !== "n/a" ? p : ""].filter(Boolean).join(" ").trim();
    if (lbl && !affectedList.includes(lbl) && affectedList.length < 6) affectedList.push(lbl);
    for (const ver of Array.isArray(a.versions) ? a.versions : []) {
      if (ver.status === "affected") {
        let s = "";
        if (ver.lessThan) s = `< ${ver.lessThan}`;
        else if (ver.lessThanOrEqual) s = `<= ${ver.lessThanOrEqual}`;
        else if (ver.version && ver.version !== "0" && ver.version !== "unspecified") s = String(ver.version);
        if (s && !versionList.includes(s) && versionList.length < 8) versionList.push(s);
        if (ver.lessThan && !fixedList.includes(ver.lessThan) && fixedList.length < 4) fixedList.push(ver.lessThan);
      }
    }
  }

  const allMetrics = [...(Array.isArray(cna.metrics) ? cna.metrics : []), ...adps.flatMap((x) => x.metrics || [])];
  let score = null;
  let vector = "";
  let rawSev = "";
  let scoreSource = "CNA";
  let ssvcExploitation = "";
  let ssvcAutomatable = "";
  let ssvcImpact = "";

  for (const m of allMetrics) {
    const cvss = m.cvssV3_1 || m.cvssV4_0 || m.cvssV3_0 || m.cvssV2_0;
    if (cvss && score == null && typeof cvss.baseScore === "number") {
      score = cvss.baseScore;
      vector = cvss.vectorString || "";
      rawSev = String(cvss.baseSeverity || "").toUpperCase();
    }
    if (m.other?.type === "ssvc" && Array.isArray(m.other?.content?.options)) {
      for (const opt of m.other.content.options) {
        if (opt.Exploitation) {
          const ev = String(opt.Exploitation).toLowerCase();
          ssvcExploitation = ev === "active" ? "Active" : ev === "poc" ? "Preuve de concept" : "Aucune";
        }
        if (opt.Automatable) {
          ssvcAutomatable = String(opt.Automatable).toLowerCase() === "yes" ? "Oui" : "Non";
        }
        if (opt["Technical Impact"]) {
          ssvcImpact = String(opt["Technical Impact"]).toLowerCase() === "total" ? "Totale" : "Partielle";
        }
      }
    }
  }

  const cwes = [];
  const allProblems = [...(Array.isArray(cna.problemTypes) ? cna.problemTypes : []), ...adps.flatMap((x) => x.problemTypes || [])];
  for (const pt of allProblems) {
    for (const d of pt.descriptions || []) {
      const id = String(d.cweId || "").trim().toUpperCase();
      if (/^CWE-\d+$/.test(id) && !cwes.includes(id)) cwes.push(id);
    }
  }

  const cnaRefs = Array.isArray(cna.references) ? cna.references : [];
  const adpRefs = adps.flatMap((x) => x.references || []);
  const references = mergeReferenceLists(cnaRefs, adpRefs);
  const patchRef =
    references.find((r) => r.tags.includes("Patch"))?.url ||
    references.find((r) => r.tags.includes("Vendor Advisory"))?.url ||
    references.find((r) => r.tags.includes("Mitigation"))?.url ||
    "";
  const exploitRef = references.find((r) => r.tags.includes("Exploit"))?.url || "";
  const hasExploitRef = Boolean(exploitRef) || ssvcExploitation === "Preuve de concept";

  const severity = SEV_FR[rawSev] || (score == null ? "NON ÉVALUÉE" : score >= 9 ? "CRITIQUE" : score >= 7 ? "ÉLEVÉE" : score >= 4 ? "MOYENNE" : "FAIBLE");
  const published = meta.datePublished ? `${String(meta.datePublished).slice(0, 19)}Z` : "";
  const modified = meta.dateUpdated ? `${String(meta.dateUpdated).slice(0, 19)}Z` : published;
  const pubMs = Date.parse(published) || nowMs;
  const family = detectFamily(vendor, product, desc);

  let priority = "P4";
  let justification = "Fiche CVE officielle (CVE.org / CNA).";
  if (ssvcExploitation === "Active" || (score != null && score >= 9.0 && hasExploitRef)) {
    priority = "P1";
    justification = ssvcExploitation === "Active"
      ? "Exploitation active signalée par la CISA (SSVC)."
      : `Faille critique (${score.toFixed(1)}/10) avec preuve de concept publique.`;
  } else if (score != null && score >= 9.0) {
    priority = "P2";
    justification = `Faille de gravité critique (${score.toFixed(1)}/10) à corriger cette semaine.`;
  } else if (score != null && score >= 7.0) {
    priority = hasExploitRef ? "P2" : "P3";
    justification = `Gravité élevée (${score.toFixed(1)}/10).`;
  }

  const rec = {
    id: cveId,
    priority,
    severity,
    score,
    score_source: score != null ? scoreSource : "",
    vector,
    risk: score == null ? 20 : Math.min(95, Math.round(score * 8 + (ssvcExploitation === "Active" ? 20 : hasExploitRef ? 12 : 0))),
    vendor,
    product,
    affected: affectedList.join("; ") || [vendor, product].filter(Boolean).join(" ").trim(),
    versions: versionList.join(", "),
    pkg_fixed: fixedList.join(", "),
    cwe: cwes.join(", "),
    family,
    desc,
    status: meta.state || "",
    source: meta.assignerShortName || "",
    kev: false,
    ssvc_exploitation: ssvcExploitation,
    ssvc_automatable: ssvcAutomatable,
    ssvc_impact: ssvcImpact,
    exploit_maturity: hasExploitRef ? "Preuve de concept publique" : "",
    exploit_ref: exploitRef,
    patch_available: patchRef || fixedList.length ? "Oui" : "",
    ref_patch: patchRef,
    references,
    new: pubMs >= cutoff1,
    published,
    modified,
    justification,
  };
  rec.views = buildViewsForRecord(rec, nowMs);
  if (kevMap && kevMap.has(rec.id)) {
    applyKevToRecord(rec, kevMap.get(rec.id), nowMs);
  }
  return rec;
}

function mergeCveRecords(nvdRec, mitreRec, epssEntry, kevEntry, nowMs) {
  const base = nvdRec ? { ...nvdRec } : mitreRec ? { ...mitreRec } : null;
  if (!base) return null;
  if (nvdRec && mitreRec) {
    if (base.score == null && mitreRec.score != null) {
      base.score = mitreRec.score;
      base.severity = mitreRec.severity;
      base.vector = base.vector || mitreRec.vector;
      base.score_source = mitreRec.score_source || "CNA";
    }
    if (!base.vendor && mitreRec.vendor) base.vendor = mitreRec.vendor;
    if (!base.product && mitreRec.product) base.product = mitreRec.product;
    if (!base.affected && mitreRec.affected) base.affected = mitreRec.affected;
    if (!base.versions && mitreRec.versions) base.versions = mitreRec.versions;
    if (!base.pkg_fixed && mitreRec.pkg_fixed) base.pkg_fixed = mitreRec.pkg_fixed;
    if (!base.desc && mitreRec.desc) base.desc = mitreRec.desc;
    if (!base.family && mitreRec.family) base.family = mitreRec.family;
    if (!base.source && mitreRec.source) base.source = mitreRec.source;
    if (!base.ssvc_exploitation && mitreRec.ssvc_exploitation) base.ssvc_exploitation = mitreRec.ssvc_exploitation;
    if (!base.ssvc_automatable && mitreRec.ssvc_automatable) base.ssvc_automatable = mitreRec.ssvc_automatable;
    if (!base.ssvc_impact && mitreRec.ssvc_impact) base.ssvc_impact = mitreRec.ssvc_impact;
    const mergedCwes = Array.from(
      new Set([...(base.cwe ? base.cwe.split(/,\s*/) : []), ...(mitreRec.cwe ? mitreRec.cwe.split(/,\s*/) : [])].filter(Boolean))
    );
    base.cwe = mergedCwes.join(", ");
    base.references = mergeReferenceLists(base.references || [], mitreRec.references || []);
    if (!base.ref_patch) {
      base.ref_patch =
        base.references.find((r) => r.tags.includes("Patch"))?.url ||
        base.references.find((r) => r.tags.includes("Vendor Advisory"))?.url ||
        mitreRec.ref_patch ||
        "";
    }
    if (!base.exploit_ref) {
      base.exploit_ref = base.references.find((r) => r.tags.includes("Exploit"))?.url || mitreRec.exploit_ref || "";
    }
    if (base.ref_patch || base.pkg_fixed) base.patch_available = "Oui";
    if (base.exploit_ref && !base.exploit_maturity) base.exploit_maturity = "Preuve de concept publique";
  }
  if (epssEntry) {
    base.epss = epssEntry.epss;
    base.epss_pct = epssEntry.percentile;
    if (base.epss >= 0.5 && (base.priority === "P3" || base.priority === "P4")) {
      base.priority = "P2";
    } else if (base.epss >= 0.1 && base.score != null && base.score >= 9.0) {
      base.priority = "P1";
    }
  }
  if (kevEntry) {
    applyKevToRecord(base, kevEntry, nowMs);
  }
  base._refsLoaded = true;
  base.views = buildViewsForRecord(base, nowMs);
  return base;
}

function buildDataset(kevPayload, nvdPayload, kevOk, nvdOk) {
  const now = new Date();
  const nowIso = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  const nowMs = now.getTime();
  const cutoff90 = nowMs - 90 * 86400000;
  const cutoff7 = nowMs - 7 * 86400000;
  const cutoff1 = nowMs - 86400000;

  const rawKev = Array.isArray(kevPayload?.vulnerabilities) ? kevPayload.vulnerabilities : [];
  const fullKevMap = new Map();
  for (const k of rawKev) {
    if (k?.cveID) fullKevMap.set(String(k.cveID).toUpperCase(), k);
  }
  const recentKev = rawKev
    .filter((k) => {
      const t = Date.parse(k.dateAdded || "");
      return !Number.isNaN(t) && t >= cutoff90;
    })
    .sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));

  const kevSlice = (recentKev.length ? recentKev : rawKev.slice(-30).reverse()).slice(0, 80);
  const byId = new Map();

  for (const k of kevSlice) {
    const vendor = k.vendorProject || "";
    const product = k.product || "";
    const desc = k.shortDescription || k.vulnerabilityName || "";
    const family = detectFamily(vendor, product, desc);
    const addedMs = Date.parse(k.dateAdded || "") || nowMs;
    const isNew = addedMs >= cutoff1;
    const ransomware = k.knownRansomwareCampaignUse === "Known" ? "Known" : "";
    const risk = ransomware ? 96 : family === "Périmétrique" ? 93 : 88;
    const kevNoteRefs = String(k.notes || "")
      .split(/\s*;\s*/)
      .map((u) => ({ url: u, tags: ["Vendor Advisory"] }));
    const rec = {
      id: k.cveID,
      priority: "P1",
      severity: "CRITIQUE",
      score: ransomware ? 9.8 : 9.0,
      score_source: "CISA KEV",
      risk,
      vendor,
      product,
      affected: `${vendor} ${product}`.trim(),
      family,
      desc,
      kev: true,
      kev_due: k.dueDate || "",
      ransomware,
      ssvc_exploitation: "Active",
      patch_available: "Oui",
      references: mergeReferenceLists(kevNoteRefs),
      new: isNew,
      published: `${k.dateAdded || nowIso.slice(0, 10)}T00:00:00Z`,
      modified: `${k.dateAdded || nowIso.slice(0, 10)}T00:00:00Z`,
      justification: ransomware
        ? "Exploitée activement (catalogue CISA KEV) et utilisée par des rançongiciels."
        : "Exploitée activement par des attaquants (catalogue officiel CISA KEV).",
      plain: `Une faille dans ${vendor} ${product} (${k.vulnerabilityName || k.cveID}). ⚠️ Des pirates l'utilisent déjà dans de vraies attaques${ransomware ? ", y compris des groupes de rançongiciels" : ""}.`,
      todo: `URGENT — sous 48 h : ${k.requiredAction || "appliquer la mise à jour de sécurité de l'éditeur"}.${k.dueDate ? ` Échéance recommandée par la CISA : ${k.dueDate}.` : ""}`,
    };
    rec.ref_patch = rec.references[0]?.url || "";
    rec.views = buildViewsForRecord(rec, nowMs);
    byId.set(rec.id, rec);
  }

  const rawNvd = Array.isArray(nvdPayload?.vulnerabilities) ? nvdPayload.vulnerabilities : [];
  for (const item of rawNvd) {
    const rec = parseNvdCve(item, nowMs, cutoff1, fullKevMap);
    if (!rec) continue;
    const existing = byId.get(rec.id);
    if (existing) {
      if (rec.score != null) existing.score = rec.score;
      if (rec.vector) existing.vector = rec.vector;
      if (rec.cwe) existing.cwe = rec.cwe;
      if (rec.versions) existing.versions = rec.versions;
      if (rec.ref_patch) existing.ref_patch = rec.ref_patch;
      if (rec.exploit_ref) existing.exploit_ref = rec.exploit_ref;
      existing.references = mergeReferenceLists(existing.references || [], rec.references || []);
    } else {
      byId.set(rec.id, rec);
    }
  }

  const prioRank = { P1: 0, P2: 1, P3: 2, P4: 3 };
  const vulns = Array.from(byId.values()).sort(
    (a, b) => prioRank[a.priority] - prioRank[b.priority] || (b.risk || 0) - (a.risk || 0)
  );

  const p1Count = vulns.filter((v) => v.priority === "P1").length;
  const p2Count = vulns.filter((v) => v.priority === "P2").length;
  const kev7d = kevSlice.filter((k) => (Date.parse(k.dateAdded || "") || 0) >= cutoff7).length;
  const new24h = vulns.filter((v) => v.new).length;
  const critical7d = vulns.filter((v) => (Date.parse(v.published || "") || 0) >= cutoff7 && (v.score || 0) >= 9.0).length;

  const kpi = {
    updated: nowIso,
    new_24h: new24h,
    new_7d: vulns.filter((v) => (Date.parse(v.published || "") || 0) >= cutoff7).length,
    critical_7d: critical7d,
    kev_7d: kev7d,
    watch_7d: 0,
    alerts_7d: 0,
    p1: p1Count,
    p2: p2Count,
    weapon: 0,
    total: vulns.length,
    kev_version: kevPayload?.catalogVersion || "",
    critical_score: 9.0,
    health: {
      NVD: { fails: nvdOk ? 0 : 1 },
      "CISA KEV": { fails: kevOk ? 0 : 1 },
    },
    encrypted: false,
    repo: "",
    settings: {
      seuils: { cvss_critique: 9.0, epss_alerte: 0.5, cvss_min_parc: 7.0 },
      alertes: {
        failles_exploitees: true,
        failles_critiques: true,
        resume_horaire: true,
        maximum_par_passage: 10,
        heures_calmes: "",
        rapport_quotidien: true,
        heure_du_rapport: 7,
        courriel_niveau_minimum: 4,
      },
      historique: { jours_de_cve: 30, jours_catalogue_cisa: 90, jours_premier_passage: 7 },
      sources: {
        exploits_publics: true,
        analyse_cisa: true,
        bibliotheques_open_source: true,
        enrichissements_par_passage: 600,
      },
      suivi: { tickets: false, priorite_des_tickets: "P1" },
      affichage: { fuseau_horaire: "America/Toronto", masquer_mots_cles: false },
      mots_cles: [],
    },
    channels: {
      ntfy: false,
      courriel: false,
      webhook: false,
      inventaire: false,
      cle_nvd: false,
      excel_chiffre: false,
    },
  };

  const synthese = [
    `VulnWatch suit ${vulns.length} vulnérabilités publiées récemment ou activement exploitées. ${p1Count} demandent une action urgente (P1, sous 48 h) et ${p2Count} sont importantes (P2, cette semaine).`,
    "Pour savoir lesquelles te concernent vraiment, ajoute tes équipements et logiciels dans l'onglet « Mon parc » de la console : c'est gratuit, sans compte, et ta liste reste sur ton appareil.",
    `Dernières 24 h : ${new24h} nouvelles vulnérabilités, ${critical7d} critiques sur 7 jours, ${kev7d} ajoutée(s) au catalogue CISA KEV sur 7 jours.`,
  ];

  const stats = [];
  for (let offset = 6; offset >= 0; offset--) {
    const dayEndMs = nowMs - offset * 86400000;
    const dayStartMs = dayEndMs - 86400000;
    const dateStr = new Date(dayEndMs).toISOString().slice(0, 10);
    const inDay = vulns.filter((v) => {
      const t = Date.parse(v.published || "");
      return !Number.isNaN(t) && t > dayStartMs && t <= dayEndMs;
    });
    const upToDay = vulns.filter((v) => {
      const t = Date.parse(v.published || "");
      return !Number.isNaN(t) && t <= dayEndMs;
    });
    stats.push({
      date: dateStr,
      new: inDay.length,
      critical: inDay.filter((v) => (v.score || 0) >= 9.0).length,
      kev_added: kevSlice.filter((k) => {
        const t = Date.parse(k.dateAdded || "");
        return !Number.isNaN(t) && t > dayStartMs && t <= dayEndMs;
      }).length,
      alerts: 0,
      p1: upToDay.filter((v) => v.priority === "P1").length,
      p2: upToDay.filter((v) => v.priority === "P2").length,
    });
  }

  return {
    kpi,
    views: EXPERT_VIEWS,
    synthese,
    glossaire: GLOSSAIRE,
    vulns,
    kev: kevSlice.map((v) => ({
      cveID: v.cveID || "",
      vendorProject: v.vendorProject || "",
      product: v.product || "",
      vulnerabilityName: v.vulnerabilityName || "",
      dateAdded: v.dateAdded || "",
      shortDescription: v.shortDescription || "",
      requiredAction: v.requiredAction || "",
      dueDate: v.dueDate || "",
      knownRansomwareCampaignUse: v.knownRansomwareCampaignUse || "",
    })),
    alerts: [],
    stats,
  };
}

function buildFallbackKev() {
  return {
    catalogVersion: "local-fixture",
    vulnerabilities: [
      {
        cveID: "CVE-2024-3400",
        vendorProject: "Palo Alto Networks",
        product: "PAN-OS",
        vulnerabilityName: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        dateAdded: new Date().toISOString().slice(0, 10),
        shortDescription: "Une injection de commande dans la fonctionnalité GlobalProtect de Palo Alto Networks PAN-OS permet à un attaquant non authentifié d'exécuter du code avec les privilèges root.",
        requiredAction: "Appliquer les correctifs ou mesures d'atténuation fournis par l'éditeur.",
        dueDate: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
        knownRansomwareCampaignUse: "Unknown",
      },
    ],
  };
}

async function fetchJsonWithTimeout(url, timeoutMs = 15000, extraHeaders = {}, retries = 1) {
  let lastReason = "";
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "VulnWatch-Preview/2.0", ...extraHeaders },
      });
      if (res.ok) {
        return { data: await res.json(), ok: true, reason: "" };
      }
      lastReason = `HTTP ${res.status}${res.headers.get("message") ? ` (${res.headers.get("message")})` : ""}`;
      if (attempt < retries && (res.status === 429 || res.status >= 500)) {
        await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      return { data: null, ok: false, reason: lastReason };
    } catch (err) {
      lastReason = err?.name === "AbortError" ? `timeout (${timeoutMs} ms)` : (err?.message || "erreur réseau");
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 1200 * (attempt + 1)));
        continue;
      }
      return { data: null, ok: false, reason: lastReason };
    } finally {
      clearTimeout(timer);
    }
  }
  return { data: null, ok: false, reason: lastReason };
}

let cachedData = null;
let cachedAt = 0;
let cachedTtlMs = 0;
let inFlightData = null;
let lastGoodKev = null;
let lastGoodNvd = null;
let fullKevMapCache = new Map();
const CACHE_TTL_MS = 30 * 60 * 1000;
const FAIL_CACHE_TTL_MS = 60 * 1000;

function updateFullKevMap(kevPayload) {
  const arr = Array.isArray(kevPayload?.vulnerabilities) ? kevPayload.vulnerabilities : [];
  if (!arr.length) return;
  const next = new Map();
  for (const k of arr) {
    if (k?.cveID) next.set(String(k.cveID).toUpperCase(), k);
  }
  fullKevMapCache = next;
}

async function getFullKevMap() {
  if (fullKevMapCache.size > 0) return fullKevMapCache;
  try {
    await getLiveData();
  } catch {
    // ignore
  }
  return fullKevMapCache;
}

async function getLiveData() {
  if (cachedData && Date.now() - cachedAt < cachedTtlMs) {
    return cachedData;
  }
  if (inFlightData) {
    return inFlightData;
  }

  inFlightData = (async () => {
    const end = new Date();
    const start = new Date(end.getTime() - 7 * 86400000);
    const fmtNvd = (d) => d.toISOString().replace(/\.\d{3}Z$/, ".000");
    const nvdQuery = `${NVD_URL}?pubStartDate=${encodeURIComponent(fmtNvd(start))}&pubEndDate=${encodeURIComponent(fmtNvd(end))}&resultsPerPage=120`;
    const nvdHeaders = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};

    const [kevRes, nvdRes] = await Promise.all([
      (async () => {
        for (const url of KEV_URLS) {
          const r = await fetchJsonWithTimeout(url, 10000, {}, 1);
          if (r.ok && r.data?.vulnerabilities) return r;
        }
        return { data: null, ok: false, reason: "indisponible" };
      })(),
      fetchJsonWithTimeout(nvdQuery, 15000, nvdHeaders, 1),
    ]);

    const kevOk = Boolean(kevRes.ok && kevRes.data?.vulnerabilities);
    const nvdOk = Boolean(nvdRes.ok && nvdRes.data?.vulnerabilities);
    if (kevOk) {
      lastGoodKev = kevRes.data;
      updateFullKevMap(kevRes.data);
    }
    if (nvdOk) lastGoodNvd = nvdRes.data;
    if (!nvdOk) console.warn("NVD fetch failed:", nvdRes.reason);

    const ds = buildDataset(
      kevOk ? kevRes.data : (lastGoodKev || buildFallbackKev()),
      nvdOk ? nvdRes.data : (lastGoodNvd || { vulnerabilities: [] }),
      kevOk,
      nvdOk
    );
    if (!nvdOk && nvdRes.reason) ds.kpi.health.NVD.reason = nvdRes.reason;
    ds.kpi.channels.cle_nvd = Boolean(process.env.NVD_API_KEY);

    cachedData = ds;
    cachedAt = Date.now();
    cachedTtlMs = (kevOk && nvdOk) ? CACHE_TTL_MS : FAIL_CACHE_TTL_MS;
    return cachedData;
  })();

  try {
    return await inFlightData;
  } finally {
    inFlightData = null;
  }
}

const onlineSearchCache = new Map();
const onlineDetailCache = new Map();
const kwTotalCache = new Map();
const ONLINE_SEARCH_TTL_MS = 5 * 60 * 1000;
const ONLINE_DETAIL_TTL_MS = 15 * 60 * 1000;

function setBoundedCache(map, key, value, maxSize = 250) {
  if (map.size >= maxSize) {
    const first = map.keys().next().value;
    if (first) map.delete(first);
  }
  map.set(key, { value, at: Date.now() });
}

function getBoundedCache(map, key, ttlMs) {
  const hit = map.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > ttlMs) {
    map.delete(key);
    return null;
  }
  return hit.value;
}

async function fetchEpssBatch(cveIds) {
  const out = new Map();
  const clean = Array.from(new Set(cveIds.filter((id) => CVE_ID_RE.test(id)))).slice(0, 40);
  if (!clean.length) return out;
  const url = `${EPSS_URL}?cve=${encodeURIComponent(clean.join(","))}`;
  const res = await fetchJsonWithTimeout(url, 8000, {}, 0);
  if (res.ok && Array.isArray(res.data?.data)) {
    for (const row of res.data.data) {
      if (!row?.cve) continue;
      const epss = Number(row.epss);
      const percentile = Number(row.percentile);
      if (!Number.isNaN(epss)) {
        out.set(String(row.cve).toUpperCase(), {
          epss,
          percentile: Number.isNaN(percentile) ? null : percentile,
        });
      }
    }
  }
  return out;
}

async function lookupSingleCveOnline(cveId) {
  const id = String(cveId || "").trim().toUpperCase();
  if (!CVE_ID_RE.test(id)) return null;
  const cached = getBoundedCache(onlineDetailCache, id, ONLINE_DETAIL_TTL_MS);
  if (cached) return cached;

  const nvdHeaders = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const nowMs = Date.now();
  const cutoff1 = nowMs - 86400000;

  const [nvdRes, mitreRes, epssMap, kevMap] = await Promise.all([
    fetchJsonWithTimeout(`${NVD_URL}?cveId=${encodeURIComponent(id)}`, 15000, nvdHeaders, 1),
    fetchJsonWithTimeout(`${MITRE_CVE_URL}/${encodeURIComponent(id)}`, 10000, {}, 1),
    fetchEpssBatch([id]),
    getFullKevMap(),
  ]);

  const nvdItem = nvdRes.ok && Array.isArray(nvdRes.data?.vulnerabilities) ? nvdRes.data.vulnerabilities[0] : null;
  const nvdRec = nvdItem ? parseNvdCve(nvdItem, nowMs, cutoff1, kevMap) : null;
  const mitreRec = mitreRes.ok && mitreRes.data?.cveMetadata ? parseMitreCve5(mitreRes.data, nowMs, cutoff1, kevMap) : null;
  const kevEntry = kevMap.get(id) || null;
  const epssEntry = epssMap.get(id) || null;

  let merged = mergeCveRecords(nvdRec, mitreRec, epssEntry, kevEntry, nowMs);
  if (!merged && kevEntry) {
    merged = applyKevToRecord(
      {
        id,
        priority: "P1",
        severity: "CRITIQUE",
        score: kevEntry.knownRansomwareCampaignUse === "Known" ? 9.8 : 9.0,
        score_source: "CISA KEV",
        risk: 92,
        vendor: kevEntry.vendorProject || "",
        product: kevEntry.product || "",
        affected: `${kevEntry.vendorProject || ""} ${kevEntry.product || ""}`.trim(),
        family: detectFamily(kevEntry.vendorProject, kevEntry.product, kevEntry.shortDescription),
        desc: kevEntry.shortDescription || kevEntry.vulnerabilityName || "",
        references: mergeReferenceLists(
          String(kevEntry.notes || "")
            .split(/\s*;\s*/)
            .map((u) => ({ url: u, tags: ["Vendor Advisory"] }))
        ),
        published: kevEntry.dateAdded ? `${kevEntry.dateAdded}T00:00:00Z` : "",
        modified: kevEntry.dateAdded ? `${kevEntry.dateAdded}T00:00:00Z` : "",
        _refsLoaded: true,
      },
      kevEntry,
      nowMs
    );
    if (epssEntry) {
      merged.epss = epssEntry.epss;
      merged.epss_pct = epssEntry.percentile;
    }
  }

  const sources = [];
  if (nvdRec) sources.push("NVD");
  if (mitreRec) sources.push("CVE.org");
  if (kevEntry) sources.push("CISA KEV");
  if (epssEntry) sources.push("EPSS");

  const result = { record: merged, sources };
  if (merged) {
    setBoundedCache(onlineDetailCache, id, result, 300);
  }
  return result;
}

async function searchCvesOnline(rawQuery, page = 0, limit = 20) {
  const q = String(rawQuery || "").replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, 120);
  const safePage = Math.max(0, Math.min(500, Math.floor(Number(page) || 0)));
  const safeLimit = Math.max(1, Math.min(30, Math.floor(Number(limit) || 20)));

  if (CVE_ID_RE.test(q)) {
    const looked = await lookupSingleCveOnline(q);
    return {
      mode: "cve",
      query: q.toUpperCase(),
      page: 0,
      limit: 1,
      totalResults: looked?.record ? 1 : 0,
      hasMore: false,
      sources: looked?.sources || [],
      results: looked?.record ? [looked.record] : [],
    };
  }

  const cacheKey = `${q.toLowerCase()}|${safePage}|${safeLimit}`;
  const cached = getBoundedCache(onlineSearchCache, cacheKey, ONLINE_SEARCH_TTL_MS);
  if (cached) return cached;

  const nvdHeaders = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const nowMs = Date.now();
  const cutoff1 = nowMs - 86400000;
  const kevMap = await getFullKevMap();

  let totalResults = 0;
  let items = [];
  let nvdError = "";

  if (!q) {
    // Parcourir les dernières CVE mondiales (fenêtre 30 jours)
    const end = new Date();
    const start = new Date(end.getTime() - 30 * 86400000);
    const fmtNvd = (d) => d.toISOString().replace(/\.\d{3}Z$/, ".000");
    const baseUrl = `${NVD_URL}?pubStartDate=${encodeURIComponent(fmtNvd(start))}&pubEndDate=${encodeURIComponent(fmtNvd(end))}`;
    let total = getBoundedCache(kwTotalCache, "__recent30__", ONLINE_SEARCH_TTL_MS);
    if (total == null) {
      const probe = await fetchJsonWithTimeout(`${baseUrl}&resultsPerPage=1&startIndex=0`, 15000, nvdHeaders, 1);
      if (!probe.ok) {
        nvdError = probe.reason || "NVD indisponible";
      } else {
        total = Number(probe.data?.totalResults || 0);
        setBoundedCache(kwTotalCache, "__recent30__", total, 100);
      }
    }
    if (!nvdError && total > 0) {
      totalResults = total;
      const endIdx = total - safePage * safeLimit;
      if (endIdx > 0) {
        const startIdx = Math.max(0, endIdx - safeLimit);
        const count = endIdx - startIdx;
        const pageRes = await fetchJsonWithTimeout(`${baseUrl}&resultsPerPage=${count}&startIndex=${startIdx}`, 15000, nvdHeaders, 1);
        if (pageRes.ok && Array.isArray(pageRes.data?.vulnerabilities)) {
          items = pageRes.data.vulnerabilities.slice().reverse();
        } else {
          nvdError = pageRes.reason || "NVD indisponible";
        }
      }
    }
  } else {
    const kwKey = `kw:${q.toLowerCase()}`;
    let total = getBoundedCache(kwTotalCache, kwKey, ONLINE_SEARCH_TTL_MS);
    if (total == null) {
      const probe = await fetchJsonWithTimeout(
        `${NVD_URL}?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=1&startIndex=0`,
        15000,
        nvdHeaders,
        1
      );
      if (!probe.ok) {
        nvdError = probe.reason || "NVD indisponible";
      } else {
        total = Number(probe.data?.totalResults || 0);
        setBoundedCache(kwTotalCache, kwKey, total, 200);
        if (total === 1 && Array.isArray(probe.data?.vulnerabilities)) {
          items = probe.data.vulnerabilities;
          totalResults = 1;
        }
      }
    }
    if (!nvdError && total > 0 && !items.length) {
      totalResults = total;
      const endIdx = total - safePage * safeLimit;
      if (endIdx > 0) {
        const startIdx = Math.max(0, endIdx - safeLimit);
        const count = endIdx - startIdx;
        const pageRes = await fetchJsonWithTimeout(
          `${NVD_URL}?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=${count}&startIndex=${startIdx}`,
          15000,
          nvdHeaders,
          1
        );
        if (pageRes.ok && Array.isArray(pageRes.data?.vulnerabilities)) {
          items = pageRes.data.vulnerabilities.slice().reverse();
        } else {
          nvdError = pageRes.reason || "NVD indisponible";
        }
      }
    }
  }

  const records = items.map((it) => parseNvdCve(it, nowMs, cutoff1, kevMap)).filter(Boolean);
  if (records.length) {
    const epssMap = await fetchEpssBatch(records.map((r) => r.id));
    for (const rec of records) {
      const e = epssMap.get(rec.id);
      if (e) {
        rec.epss = e.epss;
        rec.epss_pct = e.percentile;
      }
    }
  }

  const out = {
    mode: q ? "keyword" : "recent",
    query: q,
    page: safePage,
    limit: safeLimit,
    totalResults,
    hasMore: (safePage + 1) * safeLimit < totalResults,
    sources: nvdError ? [] : ["NVD", "EPSS", "CISA KEV"],
    error: nvdError || undefined,
    results: records,
  };
  if (!nvdError) {
    setBoundedCache(onlineSearchCache, cacheKey, out, 250);
  }
  return out;
}

function escapeCsv(val) {
  const s = String(val ?? "");
  return `"${s.replace(/"/g, '""')}"`;
}

function escapeXml(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function findStaticFile(relPath) {
  const safePath = path.normalize(relPath).replace(/^(\.\.[/\\])+/, "");
  const target = safePath === "/" || safePath === "." ? "index.html" : safePath.replace(/^[/\\]+/, "");

  if (target === "vendor/d3.min.js" && fs.existsSync(D3_BUNDLE)) {
    return D3_BUNDLE;
  }

  for (const baseDir of [PUBLIC_DIR, SITE_DIR]) {
    const resolvedBase = path.resolve(baseDir);
    const full = path.resolve(resolvedBase, target);
    if ((full === resolvedBase || full.startsWith(resolvedBase + path.sep)) && fs.existsSync(full) && fs.statSync(full).isFile()) {
      return full;
    }
  }
  return null;
}

const server = http.createServer(async (req, res) => {
  try {
    const urlObj = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = decodeURIComponent(urlObj.pathname);

    const staticFile = findStaticFile(pathname);
    if (staticFile) {
      const ext = path.extname(staticFile).toLowerCase();
      const stat = fs.statSync(staticFile);
      res.writeHead(200, {
        "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
        "Content-Length": stat.size,
      });
      if (req.method === "HEAD") {
        res.end();
        return;
      }
      const stream = fs.createReadStream(staticFile);
      stream.on("error", () => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      });
      stream.pipe(res);
      return;
    }

    if (pathname === "/data.json") {
      const data = await getLiveData();
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(data));
      return;
    }

    if (pathname === "/vulns.csv") {
      const data = await getLiveData();
      const header = ["CVE", "Priorité", "Produit", "Gravité", "Exploitée (KEV)", "En clair", "Que faire"].join(",");
      const rows = data.vulns.map((r) =>
        [r.id, r.priority, r.affected, r.score ?? "", r.kev ? "Oui" : "Non", r.plain || r.desc, r.todo || ""].map(escapeCsv).join(",")
      );
      res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8" });
      res.end("\uFEFF" + [header, ...rows].join("\n"));
      return;
    }

    if (pathname === "/kev.csv") {
      const data = await getLiveData();
      const header = ["CVE", "Fournisseur", "Produit", "Date ajout", "Échéance", "Rançongiciel", "Action"].join(",");
      const rows = data.kev.map((k) =>
        [k.cveID, k.vendorProject, k.product, k.dateAdded, k.dueDate, k.knownRansomwareCampaignUse, k.requiredAction]
          .map(escapeCsv)
          .join(",")
      );
      res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8" });
      res.end("\uFEFF" + [header, ...rows].join("\n"));
      return;
    }

    if (pathname === "/feed.xml") {
      const data = await getLiveData();
      const entries = data.vulns.slice(0, 30).map(
        (r) =>
          `<entry><id>${escapeXml(r.id)}</id><title>${escapeXml(`${r.id} — ${r.affected}`)}</title><updated>${escapeXml(r.modified)}</updated><summary>${escapeXml(r.plain || r.desc)}</summary></entry>`
      );
      const xml = `<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>VulnWatch</title><updated>${escapeXml(data.kpi.updated)}</updated>${entries.join("")}</feed>`;
      res.writeHead(200, { "Content-Type": "application/atom+xml; charset=utf-8" });
      res.end(xml);
      return;
    }

    if (pathname === "/api/translate" && req.method === "POST") {
      await handleTranslate(req, res);
      return;
    }

    if (pathname === "/api/cve-search" && req.method === "GET") {
      const qParam = urlObj.searchParams.get("q") || "";
      const pageParam = urlObj.searchParams.get("page") || "0";
      const limitParam = urlObj.searchParams.get("limit") || "20";
      const result = await searchCvesOnline(qParam, pageParam, limitParam);
      res.writeHead(result.error ? 502 : 200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(result));
      return;
    }

    if (pathname === "/api/cve-refs" && req.method === "GET") {
      const idParam = (urlObj.searchParams.get("id") || "").trim().toUpperCase();
      if (!CVE_ID_RE.test(idParam)) {
        res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "Identifiant CVE invalide (format attendu : CVE-AAAA-NNNN)." }));
        return;
      }
      const looked = await lookupSingleCveOnline(idParam);
      if (!looked?.record) {
        res.writeHead(404, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: `CVE ${idParam} introuvable dans les bases en ligne.` }));
        return;
      }
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(looked));
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  } catch (err) {
    console.error("Server error:", err);
    res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Internal Server Error");
  }
});

const translationCache = new Map();
const MAX_CACHE_ENTRIES = 1000;
let genaiClient = null;

function getGenAI() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  if (!genaiClient) {
    genaiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return genaiClient;
}

function readJsonBody(req, maxBytes = 256 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function cacheKey(item) {
  const raw = JSON.stringify([item.id, item.title || "", item.desc || "", item.plain || "", item.todo || "", item.action || ""]);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function setCache(key, value) {
  if (translationCache.size >= MAX_CACHE_ENTRIES) {
    const first = translationCache.keys().next().value;
    if (first) translationCache.delete(first);
  }
  translationCache.set(key, value);
}

async function handleTranslate(req, res) {
  const sendJson = (code, obj) => {
    res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
    res.end(JSON.stringify(obj));
  };

  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(400, { error: e.message || "Requête invalide" });
  }

  const rawItems = Array.isArray(body?.items) ? body.items.slice(0, 15) : [];
  if (!rawItems.length) {
    return sendJson(200, { translations: {} });
  }

  const results = {};
  const pending = [];
  for (const raw of rawItems) {
    if (!raw || typeof raw.id !== "string" || !raw.id.trim()) continue;
    const item = {
      id: raw.id.trim(),
      title: typeof raw.title === "string" ? raw.title.slice(0, 400) : "",
      desc: typeof raw.desc === "string" ? raw.desc.slice(0, 1400) : "",
      plain: typeof raw.plain === "string" ? raw.plain.slice(0, 700) : "",
      todo: typeof raw.todo === "string" ? raw.todo.slice(0, 700) : "",
      action: typeof raw.action === "string" ? raw.action.slice(0, 700) : "",
    };
    const key = cacheKey(item);
    const hit = translationCache.get(key);
    if (hit) {
      results[item.id] = hit;
    } else {
      pending.push({ item, key });
    }
  }

  if (!pending.length) {
    return sendJson(200, { translations: results });
  }

  const ai = getGenAI();
  if (!ai) {
    return sendJson(503, { error: "Traduction indisponible : clé API Gemini non configurée sur le serveur." });
  }

  try {
    const response = await ai.models.generateContent({
      model: "gemini-4-hydrogen",
      contents: JSON.stringify(pending.map((p) => p.item)),
      config: {
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        systemInstruction:
          "Tu es un traducteur expert en cybersécurité. Traduis chaque élément fourni (champs title, desc, plain, todo, action) en français clair, naturel, fluide et fidèle au sens technique, compréhensible par une équipe informatique comme par la direction. " +
          "Conserve intacts les identifiants CVE, les noms de produits/éditeurs, les numéros de version et les sigles standards (RCE, XSS, SQL, VPN, CVSS, CISA, KEV, EPSS). " +
          "Si un champ est déjà en français correct, conserve-le ou améliore légèrement sa fluidité sans changer le sens. Si un champ d'entrée est vide, retourne une chaîne vide pour ce champ. " +
          "Ne rajoute aucun commentaire hors du JSON demandé.",
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              id: { type: Type.STRING },
              title: { type: Type.STRING },
              desc: { type: Type.STRING },
              plain: { type: Type.STRING },
              todo: { type: Type.STRING },
              action: { type: Type.STRING },
            },
            required: ["id"],
          },
        },
      },
    });

    const parsed = JSON.parse((response.text ?? "[]").trim());
    const keyById = new Map(pending.map((p) => [p.item.id, p.key]));
    if (Array.isArray(parsed)) {
      for (const entry of parsed) {
        if (!entry?.id || !keyById.has(entry.id)) continue;
        const clean = {
          title: entry.title || "",
          desc: entry.desc || "",
          plain: entry.plain || "",
          todo: entry.todo || "",
          action: entry.action || "",
        };
        setCache(keyById.get(entry.id), clean);
        results[entry.id] = clean;
      }
    }
    return sendJson(200, { translations: results });
  } catch (err) {
    console.error("Gemini translate error:", err);
    const status = Number(err?.status || err?.code) || 502;
    const msg =
      status === 429
        ? "Quota de traduction momentanément atteint. Réessaie dans quelques instants."
        : "Impossible de traduire automatiquement les fiches pour le moment.";
    return sendJson(status >= 400 && status < 600 ? status : 502, { error: msg });
  }
}

server.listen(PORT, HOST, () => {
  console.log(`VulnWatch preview server listening on http://${HOST}:${PORT}`);
});
