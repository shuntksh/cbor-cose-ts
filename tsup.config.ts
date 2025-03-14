import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ["./src/mod.ts", "./src/cbor.ts", "./src/cose.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  outDir: "dist",
}); 