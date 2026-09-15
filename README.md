# defendml-api
DefendML Cloudflare Worker API - Authentication and security endpoints

## Reproducible release workflow

Use Node 25.8.1 and npm 11.11.0 (exact recorded reconstruction toolchain), then
`npm ci --ignore-scripts`. Wrangler 4.111.0 and esbuild 0.28.1 are local,
lockfile-pinned development tools, not Worker runtime dependencies. These pins
reproduce the existing artifact; they are not a claim that the toolchain is
current or vulnerability-free. Review toolchain maintenance separately.

1. Run `npm test` and the application authorization-grant contract test.
2. Review and commit intended changes. All provenance commands require a clean
   checkout. Never include environment files, credentials, raw API responses or
   private customer data.
3. Run `npm run provenance:build`. Ignored `dist/build.json` records the actual
   clean commit, exact Node/npm/Wrangler/esbuild versions, lock hash, source hash,
   public compatibility settings, build options and Worker SHA-256. Repeat the
   build to check determinism. Keep the lockfile committed.
4. Only when a code deployment is needed, run `npm run worker:deploy`. It rebuilds
   from the clean commit and uses local Wrangler to upload the hashed module with
   `--no-bundle --keep-vars`, annotating the version with commit and hash. This
   does not change secret values. Review configuration changes separately before
   deploying; the artifact hash does not certify binding configuration.
5. Independently inspect the authenticated Cloudflare active deployment metadata
   and hash the actual deployed JavaScript module. Do not copy raw responses or
   secret bindings. Confirm 100% traffic, compatibility settings and root HTTP 200.
6. Supply ONLY the sanitized observation object below on stdin to
   `npm run provenance:record`. The command rebuilds, validates the supplied
   metadata against its hash, checks live HTTP health, and writes an immutable
   `provenance/<versionId>.json`. Review and commit the receipt separately.

Observation fields: `versionId`, `deploymentId` (Cloudflare UUIDs), `deployedAt`
(UTC ISO timestamp from Cloudflare), `operator` (non-sensitive handle), `kind`
(`code`, `configuration-only`, or `existing-deployment-adoption`),
`artifactSHA256`, `compatibilityDate`, `compatibilityFlags`, `trafficPercent`.
For `configuration-only`, also provide `previousVersionId`; its committed receipt
must exist and have the same artifact hash. Record each subsequent configuration
revision, even if code is unchanged. Never record configuration values.

The observation is operator-attested: this tool does not authenticate to or fetch
Cloudflare metadata itself. A receipt is only valid evidence after the independent
metadata/module inspection in step 5. Its creation time is distinct from the
Cloudflare deployment time. Existing-deployment adoption proves reconstruction,
not that a newly created tooling commit was historically deployed. Failed checks
or missing inspection mean release HOLD. Do not redeploy simply to manufacture a
new version ID. A deployment command succeeding is not production verification.

Historical baseline: source `2886f32570a7428cbed8058fb70ce67c4ba2682d`,
145,823-byte module, SHA-256
`406c94541690fc3df27443f6a7b815d71f28f3f5af1085306c5f2a98deb88756`.
Historical deployment used Wrangler 4.111.0, esbuild 0.28.1, npm and Node major 25;
historical Node patch and npm version remain UNKNOWN. Grant-based authorization
is canonical; the obsolete `authorization_confirmed` boolean must not return.
