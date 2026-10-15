import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  root: import.meta.dirname,
  plugins: [
    cloudflareTest({
      main: "./test/key-store.worker.mjs",
      remoteBindings: false,
      miniflare: {
        compatibilityDate: "2026-09-04",
        durableObjects: {
          EAR_TAG_KEYS: { className: "KeyStoreDO", useSQLite: true },
        },
      },
    }),
  ],
  test: { include: ["test/key-store.cloudflare.test.mjs"] },
});
