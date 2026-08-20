// Entry — boot only. The cell self-registers on import; appId, title, version
// and baseDir come from deno.json and this file's location.
import { issues } from "./cell/issues.ts";
import { aio } from "aio";

await aio.run({
  // Pinned here rather than inferred: the id keys the data directory, and a
  // compiled binary cannot read deno.json to find it out.
  appId: "fixable",

  ui: { width: 1180, height: 820 },

  onStart: () => {
    // The restored fix log outlived the undo handles that made its entries
    // reversible — retire those buttons before anyone can press one.
    issues.expireUndos();
    // Monitoring starts itself and re-arms after every pass; the opening scan
    // gives the window something true to show the moment it appears.
    issues.monitor();
    issues.scan();
  },
});
