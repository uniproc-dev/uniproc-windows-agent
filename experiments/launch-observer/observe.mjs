import * as frida from 'frida';
import { spawn } from 'node:child_process';
import { readFileSync, appendFileSync, mkdirSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const logdir = join(root, 'logs');
mkdirSync(logdir, { recursive: true });
const log = join(logdir, new Date().toISOString().replaceAll(':', '-') + '.jsonl');
const stopFile = join(root, 'STOP');
if (existsSync(stopFile)) unlinkSync(stopFile);
writeFileSync(join(logdir, 'latest.txt'), log);
const duration = Number(process.env.LAUNCH_OBSERVER_SECONDS ?? 1800);
const targets = new Set((process.env.LAUNCH_OBSERVER_TARGETS ?? 'explorer.exe,StartMenuExperienceHost.exe,SearchHost.exe').toLowerCase().split(','));
const attached = new Map();
const failures = new Map();
let stopping = false;
let scanning = false;
function emit(record) {
    const line = JSON.stringify({ at: new Date().toISOString(), ...record });
    appendFileSync(log, line + '\n');
    process.stdout.write(line + '\n');
}
const registry = spawn('pwsh.exe', ['-NoLogo', '-NoProfile', '-File', join(root, 'userassist.ps1')], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let buffer = '';
registry.stdout.setEncoding('utf8');
registry.stdout.on('data', chunk => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, end).trim();
        buffer = buffer.slice(end + 1);
        if (line) { try { emit(JSON.parse(line)); } catch { emit({ source: 'userassist', event: 'raw', line }); } }
    }
});
registry.stderr.on('data', data => emit({ source: 'userassist', event: 'stderr', text: data.toString() }));
registry.on('error', error => emit({ source: 'userassist', event: 'spawn-error', error: String(error) }));
registry.on('exit', code => emit({ source: 'userassist', event: 'exit', code }));
const source = readFileSync(join(root, 'shell-hook.js'), 'utf8');
const device = await frida.getLocalDevice();
async function scan() {
    if (scanning || stopping) return;
    scanning = true;
    try {
        const processes = await device.enumerateProcesses();
        const present = new Set(processes.map(p => p.pid));
        for (const pid of failures.keys()) if (!present.has(pid)) failures.delete(pid);
        for (const p of processes) {
            if (!targets.has(p.name.toLowerCase()) || attached.has(p.pid) || failures.has(p.pid)) continue;
            try {
                const session = await device.attach(p.pid);
                attached.set(p.pid, { session, name: p.name });
                session.detached.connect((reason, crash) => {
                    attached.delete(p.pid);
                    emit({ source: 'shell', event: 'detached', pid: p.pid, name: p.name, reason, crash: crash?.summary ?? null });
                });
                const script = await session.createScript(source);
                script.message.connect(message => {
                    if (message.type === 'send') emit({ source: 'shell', name: p.name, ...message.payload });
                    else emit({ source: 'shell', name: p.name, event: 'script-error', message });
                });
                await script.load();
                emit({ source: 'shell', event: 'attached', pid: p.pid, name: p.name });
            } catch (error) {
                failures.set(p.pid, true);
                const entry = attached.get(p.pid);
                attached.delete(p.pid);
                if (entry) await entry.session.detach().catch(() => {});
                emit({ source: 'shell', event: 'attach-error', pid: p.pid, name: p.name, error: String(error) });
            }
        }
    } catch (error) { emit({ source: 'shell', event: 'scan-error', error: String(error) }); }
    finally { scanning = false; }
}
async function stop(reason) {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    clearInterval(control);
    registry.kill();
    for (const { session } of attached.values()) await session.detach().catch(() => {});
    emit({ source: 'observer', event: 'stopped', reason });
    process.exit(0);
}
emit({ source: 'observer', event: 'started', log, durationSeconds: duration, targets: [...targets] });
const timer = setInterval(scan, 3000);
const control = setInterval(() => { if (existsSync(stopFile)) void stop('STOP file'); }, 500);
process.on('SIGINT', () => void stop('SIGINT'));
process.on('SIGTERM', () => void stop('SIGTERM'));
setTimeout(() => void stop('duration'), duration * 1000);
await scan();
