/* Bounded read-only DT inventory. Does not invoke reboot or write properties. */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const root = "/sys/firmware/devicetree/base";
const queue = [{ p: root, depth: 0 }];
const nodes = [];
const modeProperties = [];
let cursor = 0, depthPruned = 0, errors = 0;
while (cursor < queue.length && cursor < 15000) {
  const { p, depth } = queue[cursor++];
  let entries;
  try { entries = fs.readdirSync(p, { withFileTypes: true }); }
  catch { errors++; continue; }
  const relative = p.slice(root.length) || "/";
  let compatible = "";
  try { compatible = fs.readFileSync(path.join(p, "compatible")).toString("utf8"); }
  catch { /* Optional DT property. */ }
  const relevant = /reboot|power-on|pshold|ps-hold|restart|pon@/i.test(
    path.basename(p) + " " + compatible);
  const properties = {};
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const isMode = /^mode-/.test(entry.name);
    if (!(isMode || (relevant && (entry.name === "compatible" ||
        /reboot|warm-reset|reason|restart/.test(entry.name))))) continue;
    try {
      const filename = path.join(p, entry.name);
      if (fs.statSync(filename).size > 1024) { errors++; continue; }
      const b = fs.readFileSync(filename);
      if (b.length > 1024) { errors++; continue; }
      const value = { size: b.length, hex: b.toString("hex") };
      if (entry.name === "compatible") value.text = b.toString("utf8").replace(/\0/g, ",");
      if (b.length && b.length % 4 === 0) value.cells_be = Array.from(
        { length: b.length / 4 }, (_, i) => "0x" + b.readUInt32BE(i * 4).toString(16));
      if (relevant) properties[entry.name] = value;
      if (isMode) modeProperties.push({ path: relative, name: entry.name, ...value });
    } catch { errors++; }
  }
  if (relevant) nodes.push({ path: relative, properties,
    children: entries.filter(e => e.isDirectory()).map(e => e.name) });
  for (const entry of entries) if (entry.isDirectory()) {
    if (depth < 32) queue.push({ p: path.join(p, entry.name), depth: depth + 1 });
    else depthPruned++;
  }
}
console.log(JSON.stringify({ kind: "read-only reboot-mode device-tree inventory",
  visited: cursor, limit_reached: cursor < queue.length, depth_pruned: depthPruned,
  read_errors: errors, nodes, mode_properties: modeProperties,
  hardware_writes_or_reboots: false }));
