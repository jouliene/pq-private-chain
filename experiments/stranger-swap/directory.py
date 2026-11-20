"""Short-lived public maker advertisements for the SWP1 research network."""
import ipaddress
import json
import socket
import socketserver
import struct
import threading
import time

NETWORK = '7384e1f6a0114d698310e66965beed74870d394214fc5386421d6d4b339f9eac'
SERVICE = 'token-for-native'
DEFAULT_RELAYS = ('127.0.0.1:24871', '127.0.0.1:24872')
MAX_TTL = 600
MAX_ADS = 24
MAX_FRAME = 512 * 1024
FIELDS = {'version','network','service','issued','expires','endpoint','identity','cert_sha256','signature'}


def endpoint(value):
    if not isinstance(value, str):
        raise ValueError('expected a text endpoint')
    host, port = value.rsplit(':', 1)
    if str(ipaddress.IPv4Address(host)) != host or not port.isascii() or not port.isdecimal():
        raise ValueError('expected an IPv4 service endpoint')
    n = int(port)
    if str(n) != port or not 1024 <= n <= 65535:
        raise ValueError('expected a high TCP port')
    return host, n


def validate(ad, at=None):
    from market_transport import verify_advert
    at = int(time.time()) if at is None else at
    if not isinstance(ad, dict) or set(ad) != FIELDS or type(ad['version']) is not int or ad['version'] != 1:
        raise ValueError('unsupported advertisement')
    if ad['network'] != NETWORK or ad['service'] != SERVICE:
        raise ValueError('wrong advertisement network or service')
    if (type(ad['issued']) is not int or type(ad['expires']) is not int or
            not ad['issued'] <= at < ad['expires'] <= ad['issued'] + MAX_TTL):
        raise ValueError('advertisement expired or outside its permitted lifetime')
    endpoint(ad['endpoint'])
    if len(encode(ad)) > 16384:
        raise ValueError('oversized advertisement')
    return verify_advert(ad)


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, ensure_ascii=True, allow_nan=False).encode()


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def frame(value):
    raw = encode(value)
    if not 1 <= len(raw) <= MAX_FRAME:
        raise ValueError('invalid directory frame size')
    return struct.pack('!I', len(raw)) + raw


def read_frame(stream, limit):
    hdr = stream.read(4)
    if len(hdr) != 4:
        raise ValueError('incomplete directory header')
    size, = struct.unpack('!I', hdr)
    if not 0 < size <= limit:
        raise ValueError('invalid directory frame size')
    raw = stream.read(size)
    if len(raw) != size:
        raise ValueError('incomplete directory frame')
    return json.loads(raw, object_pairs_hook=unique), size + 4


def call(address, payload, counter):
    outgoing = frame(payload)
    counter.update(request_B=0, reply_B=0)
    with socket.create_connection(endpoint(address), timeout=4) as conn:
        conn.settimeout(8)
        conn.sendall(outgoing)
        counter['request_B'] = len(outgoing)
        with conn.makefile('rb') as stream:
            result, counter['reply_B'] = read_frame(stream, MAX_FRAME)
    if not isinstance(result, dict) or result.get('ok') is not True:
        raise ValueError('directory rejected request')
    return result


class Directory:
    def __init__(self):
        self.entries = {}
        self.lock = threading.Lock()

    def dispatch(self, body):
        now = int(time.time())
        if not isinstance(body, dict):
            raise ValueError('invalid request')
        register = set(body) == {'op','ad'} and body['op'] == 'register'
        if register:
            ad = body['ad']
            ident = validate(ad, now)
        elif body != {'op':'list','network':NETWORK,'service':SERVICE}:
            raise ValueError('unknown directory request')
        with self.lock:
            self.entries = {k:v for k,v in self.entries.items() if v['expires'] > now}
            if register:
                if ident not in self.entries and len(self.entries) >= MAX_ADS:
                    raise ValueError('directory full')
                self.entries[ident] = ad
                return {'ok':True,'id':ident}
            return {'ok':True,'ads':[self.entries[k] for k in sorted(self.entries)]}


class Relay(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        self.directory = Directory()
        self.slots = threading.BoundedSemaphore(6)
        super().__init__(endpoint(address), Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()


class Handler(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self):
        try:
            request, _ = read_frame(self.rfile, 18000)
            result = self.server.directory.dispatch(request)
        except (OSError, ValueError, TypeError, RecursionError, KeyError):
            result = {'ok':False}
        try:
            self.wfile.write(frame(result))
        except OSError:
            pass


def directory_round(relays, ad=None):
    payload = {'op':'list','network':NETWORK,'service':SERVICE} if ad is None else {'op':'register','ad':ad}
    wanted = validate(ad) if ad is not None else None
    accepted, counters = {}, []
    for address in relays:
        meter = {'relay':address,'ok':False}
        counters.append(meter)
        try:
            result = call(address, payload, meter)
            if ad is None:
                ads = result.get('ads')
                if not isinstance(ads,list) or len(ads)>MAX_ADS:
                    raise ValueError('invalid inventory')
                for item in ads:
                    try:
                        accepted[validate(item)] = item
                    except (ValueError,TypeError,KeyError):
                        continue
            elif result.get('id') != wanted:
                raise ValueError('wrong publication acknowledgement')
            meter['ok'] = True
        except (OSError,ValueError,TypeError,KeyError):
            continue
    if not any(m['ok'] for m in counters):
        raise ValueError('no bootstrap relay available')
    return accepted, counters
