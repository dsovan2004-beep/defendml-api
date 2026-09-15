import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const read = name => fs.readFileSync(path.join(root, name));
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const pkg = () => JSON.parse(read('package.json'));
const installed = name => JSON.parse(read(`node_modules/${name}/package.json`)).version;
export const buildOptions = Object.freeze({ entryPoints: ['worker.js'], bundle: true,
  write: false, format: 'esm', target: 'es2022', keepNames: true,
  sourcemap: 'linked', outfile: 'dist/worker.js' });

function cleanCommit() {
  if (git('status', '--porcelain')) throw new Error('Commit or remove pending repository changes first.');
  return git('rev-parse', 'HEAD');
}

function toolchain() {
  const p = pkg();
  const npm = execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim();
  if (process.versions.node !== p.engines.node || npm !== p.engines.npm) throw new Error('Use the exact repository Node/npm pins.');
  for (const name of ['wrangler', 'esbuild']) {
    if (installed(name) !== p.devDependencies[name]) throw new Error('Run npm ci with the pinned toolchain.');
  }
  const lock = JSON.parse(read('package-lock.json'));
  for (const name of ['wrangler', 'esbuild']) {
    if (lock.packages[`node_modules/${name}`].version !== installed(name)) throw new Error('Installed toolchain differs from lock.');
  }
  return { node: process.versions.node, npm, wrangler: installed('wrangler'), esbuild: installed('esbuild') };
}

function config() {
  // Extract public runtime metadata only; never serialize config contents or vars.
  const text = read('wrangler.toml').toString();
  const date = text.match(/^compatibility_date\s*=\s*"([0-9-]+)"/m)?.[1];
  const flags = text.match(/^compatibility_flags\s*=\s*(\[[^\n]*\])/m)?.[1];
  if (!date || !/^name\s*=\s*"defendml-api"/m.test(text)) throw new Error('Unexpected Worker configuration.');
  return { compatibilityDate: date, compatibilityFlags: flags ? JSON.parse(flags) : [] };
}

export async function prepare() {
  const sourceCommit = cleanCommit();
  const tools = toolchain();
  const output = await build({ ...buildOptions, absWorkingDir: root });
  const artifact = output.outputFiles.find(f => f.path.endsWith('/worker.js'));
  const manifest = { schema: 1, service: 'defendml-api', sourceCommit,
    workerSourceSHA256: hash(read('worker.js')), lockSHA256: hash(read('package-lock.json')),
    toolchain: tools, runtime: config(), buildCommand: 'npm run provenance:build',
    buildOptions, artifact: { file: 'worker.js', bytes: artifact.contents.length, sha256: hash(artifact.contents) } };
  if (cleanCommit() !== sourceCommit) throw new Error('Source changed during build.');
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  for (const f of output.outputFiles) fs.writeFileSync(f.path, f.contents);
  fs.writeFileSync(path.join(root, 'dist/build.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

export function receipt(manifest, observation, health, predecessor) {
  const fields = ['versionId', 'deploymentId', 'deployedAt', 'operator', 'kind', 'previousVersionId', 'artifactSHA256', 'compatibilityDate', 'compatibilityFlags', 'trafficPercent'];
  if (Object.keys(observation).some(k => !fields.includes(k))) throw new Error('Unexpected observation field; never supply raw Cloudflare responses.');
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
  for (const k of ['versionId', 'deploymentId']) if (!uuid.test(observation[k] || '')) throw new Error('Invalid deployment identifier.');
  if (observation.previousVersionId && !uuid.test(observation.previousVersionId)) throw new Error('Invalid predecessor.');
  if (observation.previousVersionId === observation.versionId) throw new Error('Revision cannot be its own predecessor.');
  if (!['code', 'configuration-only', 'existing-deployment-adoption'].includes(observation.kind)) throw new Error('Invalid revision kind.');
  if (observation.kind === 'configuration-only' && !observation.previousVersionId) throw new Error('Configuration revision needs predecessor.');
  if (observation.kind === 'configuration-only' &&
      (!predecessor || predecessor.deployment.versionId !== observation.previousVersionId ||
       predecessor.build.artifact.sha256 !== manifest.artifact.sha256)) throw new Error('Configuration revision must preserve a recorded predecessor artifact.');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(observation.operator || '')) throw new Error('Use a non-sensitive operator handle.');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(observation.deployedAt || '') || !Number.isFinite(Date.parse(observation.deployedAt)) || Date.parse(observation.deployedAt) > Date.now()) throw new Error('Invalid deployment timestamp.');
  if (observation.artifactSHA256 !== manifest.artifact.sha256) throw new Error('Deployed artifact hash differs from clean build.');
  if (observation.compatibilityDate !== manifest.runtime.compatibilityDate || JSON.stringify(observation.compatibilityFlags) !== JSON.stringify(manifest.runtime.compatibilityFlags)) throw new Error('Runtime metadata differs.');
  if (observation.trafficPercent !== 100 || health !== 200) throw new Error('Require active deployment and successful health verification.');
  return { schema: 1, build: manifest, deployment: observation,
    verification: { verifiedAt: new Date().toISOString(), workerRootHTTP: health,
      method: 'Authenticated Cloudflare active-version metadata and independently hashed deployed module; operator-attested observation',
      scope: 'Code artifact and public runtime metadata only; secret values are neither inspected nor certified' } };
}

async function main() {
  const action = process.argv[2];
  if (action === 'build') return console.log(JSON.stringify(await prepare(), null, 2));
  if (action === 'record') {
    // Rebuild instead of trusting a potentially stale dist/build.json.
    const manifest = await prepare();
    const observation = JSON.parse(fs.readFileSync(0, 'utf8'));
    const response = await fetch('https://defendml-api.dsovan2004.workers.dev/', { redirect: 'error', signal: AbortSignal.timeout(15000) });
    const previous = observation.kind === 'configuration-only' && /^[a-f0-9-]{36}$/.test(observation.previousVersionId || '')
      ? JSON.parse(read(`provenance/${observation.previousVersionId}.json`)) : undefined;
    const record = receipt(manifest, observation, response.status, previous);
    const dir = path.join(root, 'provenance');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${observation.versionId}.json`), JSON.stringify(record, null, 2) + '\n', { flag: 'wx' });
    console.log('Verified deployment receipt written; review and commit it separately.');
    return;
  }
  if (action === 'deploy') {
    const manifest = await prepare();
    // Upload the already-hashed module without rebuilding it. Keep remote vars.
    const args = ['node_modules/wrangler/bin/wrangler.js', 'deploy', 'dist/worker.js',
      '--no-bundle', '--keep-vars', '--message', `source:${manifest.sourceCommit} sha256:${manifest.artifact.sha256}`];
    const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit',
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
    if (result.status !== 0) throw new Error('Deployment did not complete; inspect safely before retrying.');
    console.log('Deployment is NOT closed until independently verified and provenance:record succeeds.');
    return;
  }
  throw new Error('Expected build, record, or deploy.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('Provenance operation failed. Check pins, clean status, and sanitized observation contract.'); process.exitCode = 1; });
}
