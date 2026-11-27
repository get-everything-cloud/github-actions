"use strict";

// KVault action: requests the job's GitHub OIDC token, calls KVault's
// GET /api/oidc/secrets/<name> for each mapped secret, masks every value
// and writes it to $GITHUB_ENV. No dependencies: the runner protocol (inputs,
// workflow commands, GITHUB_ENV) is implemented directly.

const fs = require("node:fs");
const crypto = require("node:crypto");

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
// The runner owns these prefixes; overriding them can break later steps.
const RESERVED_ENV = /^(GITHUB_|RUNNER_|ACTIONS_)/i;
// Lines of a multi-line secret shorter than this are not masked on their own,
// so short fragments such as "}" do not blank out unrelated log text.
const MIN_LINE_MASK = 4;
const MAX_ERROR_DETAIL = 300;

function input(env, name, { required = true } = {}) {
  const value = (env[`INPUT_${name.toUpperCase()}`] || "").trim();
  if (required && !value) throw new Error(`Input "${name}" is required.`);
  return value;
}

// Parses lines of the form "<secret-name>=<ENV_VAR>". Splits on the last "="
// because an env var name cannot contain one.
function parseMappings(text) {
  const mappings = [];
  const seenEnv = new Set();
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const at = line.lastIndexOf("=");
    const name = at > 0 ? line.slice(0, at).trim() : "";
    const envVar = at > 0 ? line.slice(at + 1).trim() : "";
    if (!name || !envVar) {
      throw new Error(`secrets line ${i + 1}: expected "<secret-name>=<ENV_VAR>", got "${line}".`);
    }
    if (!ENV_NAME.test(envVar)) {
      throw new Error(`secrets line ${i + 1}: "${envVar}" is not a valid environment variable name.`);
    }
    if (RESERVED_ENV.test(envVar)) {
      throw new Error(`secrets line ${i + 1}: "${envVar}" uses a prefix reserved by the runner (GITHUB_, RUNNER_, ACTIONS_).`);
    }
    if (seenEnv.has(envVar)) {
      throw new Error(`secrets line ${i + 1}: "${envVar}" is mapped more than once.`);
    }
    seenEnv.add(envVar);
    mappings.push({ name, envVar });
  });
  if (!mappings.length) throw new Error('Input "secrets" contains no mappings.');
  return mappings;
}

function escapeData(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

// The runner masks per log line, so a multi-line value is also masked line
// by line in addition to the whole value.
function mask(value, out) {
  if (!value) return;
  out(`::add-mask::${escapeData(value)}`);
  if (!/[\r\n]/.test(value)) return;
  for (const line of value.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length >= MIN_LINE_MASK) out(`::add-mask::${escapeData(t)}`);
  }
}

function checkBaseUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`Input "url" is not a valid URL: "${raw}".`);
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(local && u.protocol === "http:")) {
    throw new Error(`Input "url" must use https (got "${u.protocol}").`);
  }
  return raw.replace(/\/+$/, "");
}

async function getIdToken(env, audience) {
  const reqUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!reqUrl || !reqToken) {
    throw new Error("No GitHub OIDC token is available to this job. Add `permissions: id-token: write` to the job or workflow.");
  }
  const u = new URL(reqUrl);
  u.searchParams.set("audience", audience);
  const res = await fetch(u, { headers: { Authorization: `Bearer ${reqToken}`, Accept: "application/json" } });
  if (!res.ok) throw new Error(`Requesting the GitHub OIDC token failed with HTTP ${res.status}.`);
  const body = await res.json().catch(() => ({}));
  if (typeof body.value !== "string" || !body.value) {
    throw new Error("The GitHub OIDC token response did not contain a token.");
  }
  return body.value;
}

// Best-effort read of the claims a KVault trust policy matches on, used only
// to make a 403 explainable. The token is not verified here.
function describeClaims(token) {
  try {
    const c = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    const parts = [`repository ${c.repository} (id ${c.repository_id})`, `ref ${c.ref}`];
    if (c.environment) parts.push(`environment ${c.environment}`);
    return parts.join(", ");
  } catch {
    return "unknown claims";
  }
}

function detail(body) {
  const msg = body && typeof body.error === "string" ? body.error : "";
  return msg.length > MAX_ERROR_DETAIL ? `${msg.slice(0, MAX_ERROR_DETAIL)}...` : msg;
}

async function fetchSecret(baseUrl, token, name) {
  const url = `${baseUrl}/api/oidc/secrets/${encodeURIComponent(name)}`;
  // redirect: "manual" so a Cloudflare Access login redirect is reported
  // instead of followed to an HTML page.
  const res = await fetch(url, {
    redirect: "manual",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  const accessHint =
    "This usually means Cloudflare Access is in front of /api/oidc/* without a Bypass policy for that path.";
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`KVault redirected the request for "${name}" (HTTP ${res.status}). ${accessHint}`);
  }
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`KVault returned a non-JSON response for "${name}" (HTTP ${res.status}). ${accessHint}`);
  }
  if (res.ok && typeof body.value === "string") return body.value;

  const msg = detail(body);
  switch (res.status) {
    case 401:
      throw new Error(`KVault rejected the OIDC token (HTTP 401). Check that the "audience" input equals the instance's GH_OIDC_AUD setting.`);
    case 403:
      throw new Error(
        `KVault refused "${name}" (HTTP 403${msg ? `: ${msg}` : ""}). ` +
          `The token presents ${describeClaims(token)}. Check that a trust policy matches these claims and lists "${name}" in allowedSecretNames, ` +
          `and that the secret has no IP restriction (those are always refused on this route).`
      );
    case 404:
      throw new Error(`KVault has no secret named "${name}" (HTTP 404).`);
    case 503:
      throw new Error(`KVault's GitHub OIDC route is disabled (HTTP 503${msg ? `: ${msg}` : ""}).`);
    default:
      throw new Error(`KVault returned HTTP ${res.status} for "${name}"${msg ? `: ${msg}` : ""}.`);
  }
}

function appendEnv(file, name, value) {
  let delim;
  do {
    delim = `ghadelim_${crypto.randomUUID()}`;
  } while (value.includes(delim));
  fs.appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`, "utf8");
}

async function run(env = process.env, out = (line) => process.stdout.write(`${line}\n`)) {
  const baseUrl = checkBaseUrl(input(env, "url"));
  const audience = input(env, "audience");
  const mappings = parseMappings(input(env, "secrets"));
  if (!env.GITHUB_ENV) throw new Error("GITHUB_ENV is not set; this action must run inside a GitHub Actions job.");

  const token = await getIdToken(env, audience);
  mask(token, out);

  // Fetch everything before exporting anything, so a failure leaves no
  // partial set of variables behind for later steps.
  const cache = new Map();
  const results = [];
  for (const { name, envVar } of mappings) {
    if (!cache.has(name)) {
      const value = await fetchSecret(baseUrl, token, name);
      mask(value, out);
      cache.set(name, value);
    }
    results.push([envVar, cache.get(name)]);
    out(`Fetched ${name} into ${envVar}`);
  }
  for (const [envVar, value] of results) appendEnv(env.GITHUB_ENV, envVar, value);
}

module.exports = { parseMappings, mask, escapeData, checkBaseUrl, fetchSecret, run };

if (require.main === module) {
  run().catch((err) => {
    process.stdout.write(`::error::${escapeData(err.message)}\n`);
    process.exitCode = 1;
  });
}
