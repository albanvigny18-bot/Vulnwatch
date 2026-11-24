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
const KEV_URLS = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
];

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

function parseNvdCve(item, nowMs, cutoff1) {
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

  let vendor = "";
  let product = "";
  const configs = Array.isArray(cve.configurations) ? cve.configurations : [];
  for (const cfg of configs) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        const parts = String(m.criteria || "").split(":");
        if (parts.length >= 5) {
          vendor = parts[3].replace(/_/g, " ");
          product = parts[4].replace(/_/g, " ");
          break;
        }
      }
      if (product) break;
    }
    if (product) break;
  }

  const refs = Array.isArray(cve.references) ? cve.references : [];
  const patchRef = refs.find((r) => Array.isArray(r.tags) && r.tags.includes("Patch"))?.url || "";
  const hasExploitRef = refs.some((r) => Array.isArray(r.tags) && r.tags.includes("Exploit"));

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
  const affected = [vendor, product].filter(Boolean).join(" ").trim();

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
    family,
    desc,
    kev: false,
    exploit_maturity: hasExploitRef ? "Preuve de concept publique" : "",
    patch_available: patchRef ? "Oui" : "",
    ref_patch: patchRef,
    new: isNew,
    published,
    modified,
    justification,
  };
  rec.views = buildViewsForRecord(rec, nowMs);
  return rec;
}

function buildDataset(kevPayload, nvdPayload, kevOk, nvdOk) {
  const now = new Date();
  const nowIso = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  const nowMs = now.getTime();
  const cutoff90 = nowMs - 90 * 86400000;
  const cutoff7 = nowMs - 7 * 86400000;
  const cutoff1 = nowMs - 86400000;

  const rawKev = Array.isArray(kevPayload?.vulnerabilities) ? kevPayload.vulnerabilities : [];
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
      new: isNew,
      published: `${k.dateAdded || nowIso.slice(0, 10)}T00:00:00Z`,
      modified: `${k.dateAdded || nowIso.slice(0, 10)}T00:00:00Z`,
      justification: ransomware
        ? "Exploitée activement (catalogue CISA KEV) et utilisée par des rançongiciels."
        : "Exploitée activement par des attaquants (catalogue officiel CISA KEV).",
      plain: `Une faille dans ${vendor} ${product} (${k.vulnerabilityName || k.cveID}). ⚠️ Des pirates l'utilisent déjà dans de vraies attaques${ransomware ? ", y compris des groupes de rançongiciels" : ""}.`,
      todo: `URGENT — sous 48 h : ${k.requiredAction || "appliquer la mise à jour de sécurité de l'éditeur"}.${k.dueDate ? ` Échéance recommandée par la CISA : ${k.dueDate}.` : ""}`,
    };
    rec.views = buildViewsForRecord(rec, nowMs);
    byId.set(rec.id, rec);
  }

  const rawNvd = Array.isArray(nvdPayload?.vulnerabilities) ? nvdPayload.vulnerabilities : [];
  for (const item of rawNvd) {
    const rec = parseNvdCve(item, nowMs, cutoff1);
    if (!rec) continue;
    const existing = byId.get(rec.id);
    if (existing) {
      if (rec.score != null) existing.score = rec.score;
      if (rec.vector) existing.vector = rec.vector;
      if (rec.ref_patch) existing.ref_patch = rec.ref_patch;
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

async function fetchJsonWithTimeout(url, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "VulnWatch-Preview/2.0" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

let cachedData = null;
let cachedAt = 0;
const CACHE_TTL_MS = 30 * 60 * 1000;

async function getLiveData() {
  if (cachedData && Date.now() - cachedAt < CACHE_TTL_MS) {
    return cachedData;
  }

  const end = new Date();
  const start = new Date(end.getTime() - 7 * 86400000);
  const fmtNvd = (d) => d.toISOString().replace(/\.\d{3}Z$/, ".000");
  const nvdQuery = `${NVD_URL}?pubStartDate=${encodeURIComponent(fmtNvd(start))}&pubEndDate=${encodeURIComponent(fmtNvd(end))}&resultsPerPage=120`;

  const [kevPayload, nvdPayload] = await Promise.all([
    (async () => {
      for (const url of KEV_URLS) {
        const data = await fetchJsonWithTimeout(url, 6000);
        if (data?.vulnerabilities) return data;
      }
      return null;
    })(),
    fetchJsonWithTimeout(nvdQuery, 7000),
  ]);

  const kevOk = Boolean(kevPayload);
  const nvdOk = Boolean(nvdPayload?.vulnerabilities);

  cachedData = buildDataset(kevPayload || buildFallbackKev(), nvdPayload || { vulnerabilities: [] }, kevOk, nvdOk);
  cachedAt = Date.now();
  return cachedData;
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
    const full = path.join(baseDir, target);
    if (full.startsWith(baseDir) && fs.existsSync(full) && fs.statSync(full).isFile()) {
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
