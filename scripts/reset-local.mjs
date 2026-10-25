// Deletes the desktop app's local-server data (and optionally its preferences) for development.
// Quit Malo first. Usage: npm run reset-local [-- --yes] [-- --prefs] [-- --dry-run]
import { existsSync, readdirSync, rmSync, statSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';

const ID = 'app.malo.desktop';
const args = new Set(process.argv.slice(2));
const home = homedir();

// Same locations Tauri uses for app_data_dir / app_config_dir.
function dirs() {
  switch (platform()) {
    case 'darwin': {
      const base = join(home, 'Library', 'Application Support', ID);
      return { data: base, config: base };
    }
    case 'win32': {
      const base = join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), ID);
      return { data: base, config: base };
    }
    default:
      return {
        data: join(process.env.XDG_DATA_HOME ?? join(home, '.local', 'share'), ID),
        config: join(process.env.XDG_CONFIG_HOME ?? join(home, '.config'), ID),
      };
  }
}

function size(p) {
  if (!existsSync(p)) return 0;
  const st = statSync(p);
  if (!st.isDirectory()) return st.size;
  return readdirSync(p).reduce((n, e) => n + size(join(p, e)), 0);
}

const { data, config } = dirs();
const server = join(data, 'server');
const prefs = join(config, 'preferences.json');
const targets = [server, ...(args.has('--prefs') ? [prefs] : [])].filter(existsSync);

if (targets.length === 0) {
  console.log(`Nothing to delete (looked for ${server}${args.has('--prefs') ? ` and ${prefs}` : ''}).`);
  process.exit(0);
}
console.log('This permanently deletes the local Malo server: all local users, keys, indexes and');
console.log('backups in local folder destinations. Remote destinations and IMAP servers are untouched.\n');
for (const t of targets) console.log(`  ${t}  (${(size(t) / 1024 / 1024).toFixed(1)} MiB)`);
if (args.has('--dry-run')) process.exit(0);

if (!args.has('--yes')) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question('\nQuit Malo first. Type DELETE to continue: ');
  rl.close();
  if (answer.trim() !== 'DELETE') {
    console.log('Aborted.');
    process.exit(1);
  }
}
for (const t of targets) rmSync(t, { recursive: true, force: true });
console.log('Deleted.');
