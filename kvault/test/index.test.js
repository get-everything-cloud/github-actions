"use strict";

// Runs the action against a local mock of GitHub's OIDC token endpoint and
// KVault's /api/oidc/secrets route. No network access beyond 127.0.0.1.

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseMappings, mask, run } = require("../index.js");

const claims = { repository: "reacks-io/reacks-worker", repository_id: 123, ref: "refs/tags/v1.2.3" };
const TOKEN = `h.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.s`;
const PEM = "-----BEGIN KEY-----\nAAAAsecretline1\nBBBBsecretline2\n-----END KEY-----";

const secrets = {
  "builds-rclone": { status: 200, body: { value: "rclone-value" } },
  "builds-apt-rpm-gpg": { status: 200, body: { value: PEM } },
  "not-allowed": { status: 403, body: { error: "forbidden" } },
  "ip-restricted": { status: 403, body: { error: "forbidden — this secret requires an IP restriction this auth path cannot satisfy" } },
  disabled: { status: 503, body: { error: "GitHub Actions OIDC is not enabled on this instance" } },
  "behind-access": { status: 302, headers: { Location: "https://team.cloudflareaccess.com/login" } },
  "access-html": { status: 403, raw: "<html>Forbidden</html>" },
};

let server;
let base;
let requests;

before(async () => {
  server = http.createServer((req, res) => {
    requests.push(req.url);
    const u = new URL(req.url, "http://x");
    if (u.pathname === "/token") {
      assert.equal(req.headers.authorization, "Bearer runner-token");
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ value: TOKEN, audience: u.searchParams.get("audience") }));
    }
    const m = u.pathname.match(/^\/api\/oidc\/secrets\/(.+)$/);
    const s = m && secrets[decodeURIComponent(m[1])];
    if (!s || req.headers.authorization !== `Bearer ${TOKEN}`) {
      res.writeHead(404, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "not found" }));
    }
    res.writeHead(s.status, s.headers || { "Content-Type": s.raw ? "text/html" : "application/json" });
    res.end(s.raw || (s.body ? JSON.stringify(s.body) : ""));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

function setup(secretsInput, extra = {}) {
  requests = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kvault-"));
  const envFile = path.join(dir, "env");
  fs.writeFileSync(envFile, "");
  const lines = [];
  const env = {
    INPUT_URL: `${base}/`,
    INPUT_AUDIENCE: "kvault-test",
    INPUT_SECRETS: secretsInput,
    ACTIONS_ID_TOKEN_REQUEST_URL: `${base}/token?api-version=2.0`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
    GITHUB_ENV: envFile,
    ...extra,
  };
  return { env, envFile, lines, out: (l) => lines.push(l) };
}

test("parseMappings accepts comments and blank lines, rejects bad lines", () => {
  assert.deepEqual(parseMappings("# c\n\n builds-rclone = RCLONE_CONF \nname=with=eq=X"), [
    { name: "builds-rclone", envVar: "RCLONE_CONF" },
    { name: "name=with=eq", envVar: "X" },
  ]);
  assert.throws(() => parseMappings("builds-rclone"), /expected/);
  assert.throws(() => parseMappings("a=1BAD"), /not a valid/);
  assert.throws(() => parseMappings("a=GITHUB_TOKEN"), /reserved/);
  assert.throws(() => parseMappings("a=X\nb=X"), /more than once/);
  assert.throws(() => parseMappings("# only a comment"), /no mappings/);
});

test("mask escapes and masks each line of a multi-line value", () => {
  const lines = [];
  mask("ab\ncdefg\n}", (l) => lines.push(l));
  assert.deepEqual(lines, ["::add-mask::ab%0Acdefg%0A}", "::add-mask::cdefg"]);
});

test("fetches, masks and exports secrets", async () => {
  const t = setup("builds-rclone=RCLONE_CONF\nbuilds-apt-rpm-gpg=GPG_KEY\nbuilds-rclone=RCLONE_AGAIN");
  await run(t.env, t.out);

  assert.ok(requests.includes("/token?api-version=2.0&audience=kvault-test"));
  assert.equal(requests.filter((r) => r.endsWith("/builds-rclone")).length, 1, "duplicate names are fetched once");
  assert.ok(t.lines.includes("::add-mask::rclone-value"));
  assert.ok(t.lines.includes("::add-mask::AAAAsecretline1"));
  assert.ok(t.lines.some((l) => l.startsWith("::add-mask::h.")), "OIDC token is masked");
  assert.ok(!t.lines.some((l) => !l.startsWith("::add-mask::") && /rclone-value|secretline/.test(l)), "no value printed unmasked");

  const envText = fs.readFileSync(t.envFile, "utf8");
  const parsed = {};
  const re = /^(\w+)<<(\S+)\n([\s\S]*?)\n\2\n/gm;
  for (const m of envText.matchAll(re)) parsed[m[1]] = m[3];
  assert.deepEqual(parsed, { RCLONE_CONF: "rclone-value", GPG_KEY: PEM, RCLONE_AGAIN: "rclone-value" });
});

const failures = [
  ["not-allowed", /HTTP 403: forbidden\)\. The token presents repository reacks-io\/reacks-worker \(id 123\), ref refs\/tags\/v1\.2\.3/],
  ["ip-restricted", /IP restriction this auth path cannot satisfy/],
  ["disabled", /route is disabled \(HTTP 503: GitHub Actions OIDC is not enabled/],
  ["behind-access", /redirected .*HTTP 302.*Cloudflare Access/],
  ["access-html", /non-JSON response .*HTTP 403.*Cloudflare Access/],
  ["missing", /no secret named "missing" \(HTTP 404\)/],
];

for (const [name, expected] of failures) {
  test(`fails clearly and exports nothing: ${name}`, async () => {
    const t = setup(`builds-rclone=RCLONE_CONF\n${name}=OTHER`);
    await assert.rejects(run(t.env, t.out), expected);
    assert.equal(fs.readFileSync(t.envFile, "utf8"), "");
  });
}

test("explains a missing id-token permission", async () => {
  const t = setup("builds-rclone=RCLONE_CONF", { ACTIONS_ID_TOKEN_REQUEST_URL: "" });
  await assert.rejects(run(t.env, t.out), /id-token: write/);
});

test("refuses a plain-http URL that is not local", async () => {
  const t = setup("builds-rclone=RCLONE_CONF", { INPUT_URL: "http://vault.example.com" });
  await assert.rejects(run(t.env, t.out), /must use https/);
});
