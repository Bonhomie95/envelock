#!/usr/bin/env node
/*
 * Build every Envelock sensor package from sensor/.
 *
 *   node sensor/scripts/build.mjs          production build
 *   node sensor/scripts/build.mjs --dev    also allow http://localhost / 127.0.0.1
 *                                          as an Envelock server, for testing
 *                                          against a local API
 *
 * Produces, under sensor/dist/:
 *   chrome/       + envelock-sensor-chrome-<v>.zip    Chrome Web Store / Edge Add-ons
 *   firefox/      + envelock-sensor-firefox-<v>.zip   addons.mozilla.org
 *   thunderbird/  + envelock-sensor-thunderbird-<v>.xpi
 *   outlook/                                          the add-in's hosted files
 *
 * and publishes into the dashboard's public/ folder, so `vite build` ships them:
 *   public/addins/outlook/      served at https://app.envelock.org/addins/outlook/
 *   public/downloads/           the packages the dashboard links to
 *
 * Every manifest's version is written from sensor/version.json — one number,
 * so the four clients cannot drift. Every file a manifest names is checked to
 * exist in the package before it is zipped: a store rejection, or an Outlook
 * that silently shows a broken pane, is a slow way to find a typo.
 *
 * No dependencies, not even the `zip` binary: the archives are written by the
 * small ZIP writer below, with fixed timestamps, so the same source always
 * produces byte-identical packages.
 */
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deflateRawSync } from "node:zlib";

const HERE = dirname(fileURLToPath(import.meta.url));
const SENSOR = join(HERE, "..");
const CLIENT = join(SENSOR, "..");
const DIST = join(SENSOR, "dist");
const PUBLIC = join(CLIENT, "public");
const DEV = process.argv.includes("--dev");
const DEV_ORIGINS = ["http://localhost/*", "http://127.0.0.1/*"];
const ADDIN_BASE = "https://app.envelock.org/addins/outlook/";

const { version } = JSON.parse(readFileSync(join(SENSOR, "version.json"), "utf8"));
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`sensor/version.json: bad version ${version}`);

/* ── ZIP ────────────────────────────────────────────────────────────────── */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/* 2026-01-01 00:00:00 in MS-DOS format: fixed, so builds are reproducible. */
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

export function zip(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
    const nameBuf = Buffer.from(name, "utf8");
    const deflated = deflateRawSync(data, { level: 9 });
    const stored = deflated.length >= data.length;
    const body = stored ? data : deflated;
    const method = stored ? 0 : 8;
    const crc = crc32(data);

    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(0x0800, 6); /* UTF-8 names */
    head.writeUInt16LE(method, 8);
    head.writeUInt16LE(DOS_TIME, 10);
    head.writeUInt16LE(DOS_DATE, 12);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(body.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(nameBuf.length, 26);
    head.writeUInt16LE(0, 28);
    local.push(head, nameBuf, body);

    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0);
    dir.writeUInt16LE((3 << 8) | 20, 4); /* made by: Unix, spec 2.0 */
    dir.writeUInt16LE(20, 6);
    dir.writeUInt16LE(0x0800, 8);
    dir.writeUInt16LE(method, 10);
    dir.writeUInt16LE(DOS_TIME, 12);
    dir.writeUInt16LE(DOS_DATE, 14);
    dir.writeUInt32LE(crc, 16);
    dir.writeUInt32LE(body.length, 20);
    dir.writeUInt32LE(data.length, 24);
    dir.writeUInt16LE(nameBuf.length, 28);
    dir.writeUInt32LE(0, 30); /* extra + comment length */
    dir.writeUInt32LE(0, 34); /* disk + internal attrs */
    dir.writeUInt32LE((0o100644 << 16) >>> 0, 38); /* -rw-r--r-- */
    dir.writeUInt32LE(offset, 42);
    central.push(dir, nameBuf);

    offset += head.length + nameBuf.length + body.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, end]);
}

/* ── Packaging ──────────────────────────────────────────────────────────── */
function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

function copy(from, to) {
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(from, to);
}

function icons(out, sizes, nested) {
  for (const size of sizes) {
    const name = `icon-${size}.png`;
    copy(join(SENSOR, "shared/icons", name), join(out, nested ? `icons/${name}` : name));
  }
}

function writeManifest(out, source, mutate) {
  const manifest = JSON.parse(readFileSync(join(SENSOR, source), "utf8"));
  manifest.version = version;
  mutate?.(manifest);
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}

/* Every path a manifest names must be in the package. */
function assertReferenced(out, manifest) {
  const refs = [];
  const bg = manifest.background || {};
  if (bg.service_worker) refs.push(bg.service_worker);
  refs.push(...(bg.scripts || []));
  for (const cs of manifest.content_scripts || []) refs.push(...(cs.js || []), ...(cs.css || []));
  if (manifest.options_ui) refs.push(manifest.options_ui.page);
  const action = manifest.action || manifest.browser_action || {};
  if (action.default_popup) refs.push(action.default_popup);
  const actionIcon = action.default_icon;
  if (typeof actionIcon === "string") refs.push(actionIcon);
  else if (actionIcon) refs.push(...Object.values(actionIcon));
  refs.push(...Object.values(manifest.icons || {}));
  const missing = refs.filter((r) => !existsSync(join(out, r)));
  if (missing.length) throw new Error(`${relative(SENSOR, out)}: manifest names missing files: ${missing.join(", ")}`);
  return refs.length;
}

function pack(out, file) {
  const entries = walk(out).map((full) => ({
    name: relative(out, full).split(sep).join("/"),
    data: readFileSync(full),
  }));
  const data = zip(entries);
  writeFileSync(join(DIST, file), data);
  return { file, bytes: data.length, sha256: createHash("sha256").update(data).digest("hex") };
}

const BROWSER_FILES = [
  "browser/background.js",
  "browser/content.js",
  "browser/webmail.js",
  "browser/options.html",
  "browser/options.js",
  "browser/popup.html",
  "browser/popup.js",
];

function buildBrowser(target) {
  const out = join(DIST, target);
  for (const f of BROWSER_FILES) copy(join(SENSOR, f), join(out, f.split("/").pop()));
  copy(join(SENSOR, "core/envelock-sensor.js"), join(out, "envelock-sensor.js"));
  copy(join(SENSOR, "shared/ui.css"), join(out, "ui.css"));
  icons(out, [16, 32, 48, 128], true);
  const manifest = writeManifest(out, `browser/manifest.${target}.json`, (m) => {
    if (DEV) m.host_permissions = [...m.host_permissions, ...DEV_ORIGINS];
  });
  const refs = assertReferenced(out, manifest);
  return { target, refs, ...pack(out, `envelock-sensor-${target}-${version}.zip`) };
}

function buildThunderbird() {
  const out = join(DIST, "thunderbird");
  for (const f of ["background.js", "options.html", "options.js"]) {
    copy(join(SENSOR, "thunderbird", f), join(out, f));
  }
  copy(join(SENSOR, "core/envelock-sensor.js"), join(out, "envelock-sensor.js"));
  copy(join(SENSOR, "shared/ui.css"), join(out, "ui.css"));
  icons(out, [16, 32, 48, 128], true);
  const manifest = writeManifest(out, "thunderbird/manifest.json", (m) => {
    if (DEV) m.permissions = [...m.permissions, ...DEV_ORIGINS];
  });
  const refs = assertReferenced(out, manifest);
  return { target: "thunderbird", refs, ...pack(out, `envelock-sensor-thunderbird-${version}.xpi`) };
}

function buildOutlook() {
  const out = join(DIST, "outlook");
  for (const f of ["taskpane.html", "taskpane.js"]) copy(join(SENSOR, "outlook", f), join(out, f));
  copy(join(SENSOR, "core/envelock-sensor.js"), join(out, "envelock-sensor.js"));
  copy(join(SENSOR, "shared/ui.css"), join(out, "ui.css"));
  icons(out, [16, 32, 64, 80, 128], false);

  /* Office wants a four-part version. */
  const xml = readFileSync(join(SENSOR, "outlook/manifest.xml"), "utf8").replace(
    /<Version>[^<]*<\/Version>/,
    `<Version>${version}.0</Version>`,
  );
  writeFileSync(join(out, "manifest.xml"), xml);

  /* Every hosted URL in the manifest must be a file we ship. */
  const urls = [...xml.matchAll(/https:\/\/app\.envelock\.org\/addins\/outlook\/([^"#?\s<>]+)/g)].map((m) => m[1]);
  const missing = urls.filter((u) => !existsSync(join(out, u)));
  if (missing.length) throw new Error(`outlook: manifest names missing files: ${missing.join(", ")}`);
  if (!xml.includes(ADDIN_BASE)) throw new Error("outlook: manifest does not point at the hosted add-in");
  return { target: "outlook", refs: urls.length, file: "(hosted)", bytes: 0, sha256: "" };
}

function publish(results) {
  const addins = join(PUBLIC, "addins/outlook");
  rmSync(addins, { recursive: true, force: true });
  for (const full of walk(join(DIST, "outlook"))) copy(full, join(addins, relative(join(DIST, "outlook"), full)));

  const downloads = join(PUBLIC, "downloads");
  rmSync(downloads, { recursive: true, force: true });
  mkdirSync(downloads, { recursive: true });
  /* Stable names for the dashboard's links; the versioned files stay in dist
     for store uploads. */
  const stable = { chrome: "envelock-sensor-chrome.zip", firefox: "envelock-sensor-firefox.zip", thunderbird: "envelock-sensor-thunderbird.xpi" };
  for (const r of results) {
    if (stable[r.target]) copyFileSync(join(DIST, r.file), join(downloads, stable[r.target]));
  }
  writeFileSync(
    join(downloads, "sensor.json"),
    JSON.stringify(
      {
        version,
        packages: Object.fromEntries(
          results.filter((r) => stable[r.target]).map((r) => [r.target, { file: stable[r.target], sha256: r.sha256, bytes: r.bytes }]),
        ),
        outlookManifest: `${ADDIN_BASE}manifest.xml`,
      },
      null,
      2,
    ) + "\n",
  );
}

export function build() {
  rmSync(DIST, { recursive: true, force: true });
  mkdirSync(DIST, { recursive: true });
  const results = [buildBrowser("chrome"), buildBrowser("firefox"), buildThunderbird(), buildOutlook()];
  publish(results);
  return results;
}

export { crc32, DIST, version };

/* Run only when invoked directly, so the tests can import `zip` and `build`. */
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const results = build();
  console.log(`Envelock sensor ${version}${DEV ? " (dev: localhost allowed)" : ""}`);
  for (const r of results) {
    const size = r.bytes ? `${(r.bytes / 1024).toFixed(1)} KB` : "";
    console.log(`  ${r.target.padEnd(12)} ${String(r.refs).padStart(2)} refs checked  ${r.file.padEnd(40)} ${size}`);
  }
  console.log(`  published → public/addins/outlook/ and public/downloads/`);
}
