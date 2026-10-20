let installed = false;
let nextId = 0;
function install() {
    if (installed) return;
    const module = Process.findModuleByName('shell32.dll');
    if (module === null) return;
    const address = module.findExportByName('ShellExecuteExW');
    if (address === null) return;
    const wide = Process.pointerSize === 8;
    const offsets = wide
        ? { verb: 16, file: 24, parameters: 32, directory: 40, show: 48, instance: 56, process: 104, size: 112 }
        : { verb: 12, file: 16, parameters: 20, directory: 24, show: 28, instance: 32, process: 56, size: 60 };
    function stringAt(p, offset) {
        const value = p.add(offset).readPointer();
        return value.isNull() ? null : value.readUtf16String(8192);
    }
    Interceptor.attach(address, {
        onEnter(args) {
            this.id = ++nextId;
            this.info = args[0];
            this.valid = false;
            try {
                const size = this.info.readU32();
                if (size < offsets.size) throw new Error('Unexpected SHELLEXECUTEINFO size: ' + size);
                this.mask = this.info.add(4).readU32();
                this.valid = true;
                send({ event: 'enter', id: this.id, at: new Date().toISOString(), pid: Process.id, tid: this.threadId,
                    verb: stringAt(this.info, offsets.verb), file: stringAt(this.info, offsets.file),
                    parameters: stringAt(this.info, offsets.parameters), directory: stringAt(this.info, offsets.directory),
                    mask: '0x' + this.mask.toString(16), show: this.info.add(offsets.show).readS32() });
            } catch (error) {
                send({ event: 'decode-error', id: this.id, at: new Date().toISOString(), error: String(error) });
            }
        },
        onLeave(result) {
            const error = this.lastError;
            const record = { event: 'leave', id: this.id, at: new Date().toISOString(), pid: Process.id,
                ok: result.toInt32() !== 0, lastError: result.toInt32() === 0 ? error : null };
            try {
                if (this.valid) {
                    record.instanceResult = this.info.add(offsets.instance).readPointer().toString();
                    if ((this.mask & 0x40) !== 0 && record.ok) record.processHandle = this.info.add(offsets.process).readPointer().toString();
                }
            } catch (error) { record.decodeError = String(error); }
            send(record);
            this.lastError = error;
        }
    });
    installed = true;
    send({ event: 'hook-ready', at: new Date().toISOString(), pid: Process.id, api: 'shell32!ShellExecuteExW', arch: Process.arch });
}
install();
setInterval(install, 1000);
