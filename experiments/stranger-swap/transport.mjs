// One fresh hybrid TLS connection per private wallet request.
import * as tls from 'node:tls';
import * as net from 'node:net';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import {join} from 'node:path';
import {Duplex} from 'node:stream';
import {once} from 'node:events';

const maxBody = 1 << 20;
const group = 'X25519MLKEM768';
const cipher = 'TLS_AES_256_GCM_SHA384';
const alpn = 'pqd-stranger/1';
const signDomain = Buffer.from('PQD/stranger-advert/v1\0');
const channelDomain = Buffer.from('PQD/stranger-server-auth/v1\0');
const options = {minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: group,
    ciphers: cipher, ALPNProtocols: [alpn], secureOptions: crypto.constants.SSL_OP_NO_TICKET};
const sigSize = 3309;
const deadline = 150000;

function check(ok) { if (!ok) throw Error('invalid protocol'); }
function hash(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function privateKey(dir) { return crypto.createPrivateKey(fs.readFileSync(join(dir, 'advert.pem'))); }
function publicKey(encoded) {
    const bytes = Buffer.from(encoded, 'base64');
    check(bytes.length === 1974 && bytes.toString('base64') === encoded);
    const key = crypto.createPublicKey({key:bytes, type:'spki', format:'der'});
    check(key.asymmetricKeyType === 'ml-dsa-65' && key.export({format:'der',type:'spki'}).equals(bytes));
    return key;
}
function signature(value) {
    const buf = Buffer.from(value,'base64');
    check(buf.length === sigSize && buf.toString('base64') === value);
    return buf;
}
function apoint(text) {
    const [host, number, extra] = text.split(':');
    const port = Number(number);
    check(!extra && net.isIPv4(host) && port > 0 && port <= 65535 && String(port) === number);
    return {host, port};
}
function channel(socket, adID) {
    const id = Buffer.from(adID, 'hex');
    check(id.length === 32 && id.toString('hex') === adID);
    return Buffer.concat([channelDomain, id, socket.exportKeyingMaterial(48, 'EXPORTER-pqd-stranger-v1', id)]);
}
function secure(socket) {
    check(socket.getProtocol() === 'TLSv1.3' && socket.getCipher().standardName === cipher
          && socket.alpnProtocol === alpn && !socket.isSessionReused());
}
function framed(raw) {
    check(raw.length > 0 && raw.length <= maxBody);
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(raw.length);
    return Buffer.concat([prefix, raw]);
}
class Reader {
    constructor(stream) {
        this.iter = stream[Symbol.asyncIterator]();
        this.left = Buffer.alloc(0);
    }
    async take(n) {
        const dst = Buffer.allocUnsafe(n);
        let pos = 0;
        while (pos < n) {
            if (!this.left.length) {
                const next = await this.iter.next();
                check(!next.done && next.value.length);
                this.left = next.value;
            }
            const len = Math.min(n - pos, this.left.length);
            this.left.copy(dst, pos, 0, len);
            this.left = this.left.subarray(len);
            pos += len;
        }
        return dst;
    }
    async frame(bound=maxBody) {
        const n = (await this.take(4)).readUInt32BE();
        check(n > 0 && n <= bound);
        return this.take(n);
    }
}
function send(stream, data) {
    return new Promise((resolve, reject) => stream.write(framed(data), e => e ? reject(e) : resolve()));
}

// Instrument the TCP socket below TLS so both Hello flights, record headers, encrypted
// application traffic and orderly shutdown are included. No packet contents are logged.
function counted(raw, meter) {
    const wrap = new Duplex({
        read() { raw.resume(); },
        write(buf, encoding, done) {
            raw.write(buf, encoding, err => {
                if (!err) meter.wire_request_B += buf.length;
                done(err);
            });
        },
        final(done) { raw.end(done); },
        destroy(err, done) { raw.destroy(); done(err); }
    });
    raw.on('data', chunk => {
        meter.wire_reply_B += chunk.length;
        if (!wrap.push(chunk)) raw.pause();
    });
    raw.on('end', () => wrap.push(null));
    raw.on('error', err => wrap.destroy(err));
    raw.on('close', () => wrap.push(null));
    wrap.on('error', () => {});
    return wrap;
}
async function request(q) {
    const m = {wire_request_B:0, wire_reply_B:0, request_B:0, reply_B:0, authenticated:false,
               cert_pinned:false, failure:null, group:null, protocol:null, cipher:null};
    const req = Buffer.from(q.body, 'base64');
    check(req.length && req.length <= maxBody);
    const raw = net.connect(apoint(q.endpoint));
    const timer = setTimeout(() => raw.destroy(Error('deadline')), deadline);
    const authTimer = setTimeout(() => raw.destroy(Error('authentication deadline')), 8000);
    const closed = new Promise(resolve => raw.once('close', resolve));
    const stream = counted(raw, m);
    const sock = tls.connect({...options, socket:stream, rejectUnauthorized:false});
    sock.on('error', () => {});
    let response;
    let stage = 'handshake';
    try {
        await once(sock, 'secureConnect');
        secure(sock);
        m.group = sock.getEphemeralKeyInfo()?.name;
        m.protocol = sock.getProtocol();
        m.cipher = sock.getCipher().standardName;
        check(m.group === group);
        stage = 'certificate-pin';
        const cert = sock.getPeerX509Certificate();
        check(cert && hash(cert.raw).toString('hex') === q.cert_sha256);
        m.cert_pinned = true;
        stage = 'exporter-signature';
        const reader = new Reader(sock);
        const proof = await reader.frame(sigSize);
        check(proof.length === sigSize && crypto.verify(null, channel(sock, q.ad_id), publicKey(q.identity), proof));
        check(Date.now() / 1000 < q.expires);
        m.authenticated = true;
        clearTimeout(authTimer);
        stage = 'exchange';
        await send(sock, req);
        m.request_B = req.length;
        const body = await reader.frame();
        m.reply_B = body.length;
        response = {ok:true, body:body.toString('base64')};
        sock.end();
        // Consume peer close_notify and TCP FIN before publishing wire counters.
        await closed;
    } catch {
        sock.destroy();
        raw.destroy();
        await closed;
        m.failure = stage;
        response = {ok:false};
    } finally {
        clearTimeout(timer);
        clearTimeout(authTimer);
    }
    return {...response, meter:m};
}

async function serve(q, parent) {
    const dir = q.directory;
    const secret = privateKey(dir);
    const id = q.ad_id;
    const cert = fs.readFileSync(join(dir,'cert.pem'));
    check(hash(new crypto.X509Certificate(cert).raw).toString('hex') === q.cert_sha256
        && crypto.createPublicKey(secret).export({type:'spki',format:'der'}).toString('base64') === q.identity);
    let pending = null;
    let seq = 0;
    const server = tls.createServer({...options, key:fs.readFileSync(join(dir,'tls.pem')), cert,
        handshakeTimeout:8000}, async sock => {
        sock.on('error', () => {});
        const timer = setTimeout(() => sock.destroy(), 8000);
        try {
            secure(sock);
            check(Date.now()/1000 < q.expires);
            await send(sock, crypto.sign(null, channel(sock, id), secret));
            const payload = await new Reader(sock).frame();
            clearTimeout(timer);
            check(Date.now() / 1000 < q.expires);
            if (pending) {
                await send(sock, Buffer.from('{"ok":false,"error":"busy"}'));
            } else {
                const token = ++seq;
                const reply = new Promise((resolve, reject) => { pending = {token, resolve, reject}; });
                // Register the local handler before forwarding. Only the matching local
                // result can complete this operation, including after a disconnected taker.
                await writeLocal({token, body:payload.toString('base64')});
                await send(sock, await reply);
            }
            sock.end();
        } catch {
            sock.destroy();
        } finally { clearTimeout(timer); }
    });
    server.maxConnections = 8;
    server.on('connection', raw => {
        const timer = setTimeout(() => raw.destroy(), deadline);
        raw.once('close', () => clearTimeout(timer));
    });
    server.on('tlsClientError', () => {});
    const endpoint = apoint(q.listen);
    server.listen({...endpoint, backlog:8});
    await once(server, 'listening');
    await writeLocal({ready:true});
    try {
        for (;;) {
            const msg = JSON.parse(await parent.frame(localMax));
            check(pending && msg.token === pending.token);
            const body = Buffer.from(msg.body, 'base64');
            check(body.length > 0 && body.length <= maxBody);
            const task = pending;
            pending = null;
            task.resolve(body);
        }
    } finally {
        if (pending) pending.reject(Error('maker stopped'));
        server.close();
    }
}
const localMax = 2 * maxBody;
async function writeLocal(value) {
    const data = Buffer.from(JSON.stringify(value));
    check(data.length > 0 && data.length <= localMax);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(data.length);
    await new Promise((resolve, reject) => process.stdout.write(Buffer.concat([header,data]), err=>err?reject(err):resolve()));
}
// The local endpoint carries base64 over subprocess pipes, independently bounded from the network frames.
async function main() {
    check(process.versions.node === '24.22.1' && process.versions.openssl === '3.5.9');
    const parent = new Reader(process.stdin);
    const q = JSON.parse(await parent.frame(localMax));
    const op = process.argv[2];
    if (op === 'serve') return serve(q, parent);
    let result;
    if (op === 'identity') {
        const {privateKey:priv, publicKey:pub} = crypto.generateKeyPairSync('ml-dsa-65');
        fs.writeFileSync(join(q.directory,'advert.pem'), priv.export({format:'pem',type:'pkcs8'}), {flag:'wx',mode:0o600});
        const cert = new crypto.X509Certificate(fs.readFileSync(join(q.directory,'cert.pem')));
        result = {identity:pub.export({format:'der',type:'spki'}).toString('base64'),cert_sha256:hash(cert.raw).toString('hex')};
    } else if (op === 'sign' || op === 'verify') {
        const data = Buffer.from(q.payload, 'base64');
        check(data.length && data.length <= 16384);
        const signed = Buffer.concat([signDomain, data]);
        result = op === 'sign' ? {signature:crypto.sign(null, signed, privateKey(q.directory)).toString('base64')}
            : {valid:crypto.verify(null, signed, publicKey(q.identity), signature(q.signature))};
    } else if (op === 'request') result = await request(q);
    else throw Error('unknown command');
    await writeLocal(result);
}
main().catch(() => { process.exitCode = 1; });
