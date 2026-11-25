import { execFileSync } from 'node:child_process';
import { readFile, cp } from 'node:fs/promises';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--common') throw Error('Supply --common /clean/pinned/ragbaz-common');
const common = resolve(args[1]);
const lock = JSON.parse(await readFile(new URL('../common-widgets.lock.json', import.meta.url)));
const git = (...args) => execFileSync('git', ['-C', common, ...args], { encoding: 'utf8' }).trim();
if (lock.repository !== 'tabenius/ragbaz-common' || git('rev-parse', 'HEAD') !== lock.commit || git('status', '--porcelain', '--untracked-files=all')) throw Error('Common widget source must match clean pinned checkout');
await cp(resolve(common, 'src/widgets/dom.js'), 'apps/rebsync-app/dist/ragbaz-dom.js');
console.log('Synced rebsync shared DOM widgets from', lock.commit);
