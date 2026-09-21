/* The built packages: what actually ships to the stores and to Outlook. */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";

const { build, zip, crc32, DIST, version } = await import("../scripts/build.mjs");
build();

const targets = {
  chrome: join(DIST, "chrome"),
  firefox: join(DIST, "firefox"),
  thunderbird: join(DIST, "thunderbird"),
};
const manifest = (t) => JSON.parse(readFileSync(join(targets[t], "manifest.json"), "utf8"));

test("every package carries the one version from version.json", () => {
  for (const t of Object.keys(targets)) assert.equal(manifest(t).version, version, t);
  const xml = readFileSync(join(DIST, "outlook/manifest.xml"), "utf8");
  assert.match(xml, new RegExp(`<Version>${version.replace(/\./g, "\\.")}\\.0</Version>`));
});

test("no package asks for every website up front", () => {
  for (const t of ["chrome", "firefox"]) {
    const m = manifest(t);
    for (const pattern of m.host_permissions) {
      assert.notEqual(pattern, "<all_urls>", t);
      assert.notEqual(pattern, "https://*/*", `${t}: broad access must stay optional`);
    }
    assert.deepEqual(m.optional_host_permissions, ["https://*/*"]);
    assert.deepEqual(m.permissions.sort(), ["alarms", "scripting", "storage"]);
  }
  const tb = manifest("thunderbird");
  assert.equal(tb.permissions.includes("<all_urls>"), false);
  assert.equal(tb.permissions.includes("messagesModify"), false, "the sensor never changes mail");
});

test("a production build does not allow a localhost server", () => {
  for (const t of Object.keys(targets)) {
    const all = JSON.stringify(manifest(t));
    assert.equal(all.includes("localhost"), false, t);
  }
});

test("no extension page loads remote code", () => {
  for (const t of Object.keys(targets)) {
    for (const file of readdirSync(targets[t]).filter((f) => f.endsWith(".html"))) {
      const html = readFileSync(join(targets[t], file), "utf8");
      assert.equal(/<script[^>]+src=["']https?:/i.test(html), false, `${t}/${file}`);
    }
  }
});

test("the Outlook pane loads office.js from Microsoft and nothing else remote", () => {
  const html = readFileSync(join(DIST, "outlook/taskpane.html"), "utf8");
  const remote = [...html.matchAll(/<script[^>]+src=["'](https?:[^"']+)/gi)].map((m) => m[1]);
  assert.deepEqual(remote, ["https://appsforoffice.microsoft.com/lib/1/hosted/office.js"]);
});

test("the Outlook manifest is stable and points at the hosted pane", () => {
  const xml = readFileSync(join(DIST, "outlook/manifest.xml"), "utf8");
  assert.match(xml, /<Id>ebfe3fa5-992f-4328-ac78-2867f0ad6f22<\/Id>/, "changing the Id orphans every install");
  assert.match(xml, /<Permissions>ReadItem<\/Permissions>/, "never more than ReadItem");
  assert.match(xml, /<SupportsPinning>true<\/SupportsPinning>/);
  assert.match(xml, /https:\/\/app\.envelock\.org\/addins\/outlook\/taskpane\.html/);
});

test("the dashboard gets stable download names and a checksum manifest", () => {
  const client = fileURLToPath(new URL("../..", import.meta.url));
  const downloads = join(client, "public/downloads");
  for (const f of ["envelock-sensor-chrome.zip", "envelock-sensor-firefox.zip", "envelock-sensor-thunderbird.xpi"]) {
    assert.ok(existsSync(join(downloads, f)), f);
  }
  const index = JSON.parse(readFileSync(join(downloads, "sensor.json"), "utf8"));
  assert.equal(index.version, version);
  assert.match(index.packages.thunderbird.sha256, /^[0-9a-f]{64}$/);
  assert.ok(existsSync(join(client, "public/addins/outlook/manifest.xml")));
});

/* A tiny reader, independent of the writer, so the round-trip proves the
   archive rather than agreeing with itself. */
function readZip(buf) {
  const end = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = buf.readUInt16LE(end + 10);
  let p = buf.readUInt32LE(end + 16);
  const out = {};
  for (let i = 0; i < count; i++) {
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    const dataStart = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(dataStart, dataStart + size);
    out[name] = { data: method === 8 ? inflateRawSync(raw) : raw, crc };
    p += 46 + nameLen;
  }
  return out;
}

test("the zip writer round-trips, compressed and stored", () => {
  const entries = [
    { name: "manifest.json", data: Buffer.from(JSON.stringify({ a: "x".repeat(500) })) },
    { name: "icons/tiny.bin", data: Buffer.from([1, 2, 3]) },
  ];
  const back = readZip(zip(entries));
  for (const e of entries) {
    assert.deepEqual(back[e.name].data, e.data, e.name);
    assert.equal(back[e.name].crc, crc32(e.data));
  }
});
