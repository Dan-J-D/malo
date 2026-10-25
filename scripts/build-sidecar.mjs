// Builds malo-server and copies it to src-tauri/binaries/malo-server-<target-triple>[.exe],
// the name Tauri's `externalBin` expects. Usage: node scripts/build-sidecar.mjs [--debug] [--target <triple>]
import { execSync } from 'node:child_process';
import { copyFileSync, mkdirSync, chmodSync } from 'node:fs';

const args = process.argv.slice(2);
const debug = args.includes('--debug');
const ti = args.indexOf('--target');
const host = execSync('rustc -vV').toString().match(/host: (\S+)/)[1];
const target = ti >= 0 ? args[ti + 1] : host;
const profile = debug ? 'debug' : 'release';
const cargoArgs = ['build', '-p', 'malo-server', ...(debug ? [] : ['--release']), ...(ti >= 0 ? ['--target', target] : [])];
execSync(`cargo ${cargoArgs.join(' ')}`, { stdio: 'inherit' });
const ext = target.includes('windows') ? '.exe' : '';
const src = ti >= 0 ? `target/${target}/${profile}/malo-server${ext}` : `target/${profile}/malo-server${ext}`;
mkdirSync('src-tauri/binaries', { recursive: true });
const dst = `src-tauri/binaries/malo-server-${target}${ext}`;
copyFileSync(src, dst);
if (!ext) chmodSync(dst, 0o755);
console.log(`sidecar -> ${dst}`);
