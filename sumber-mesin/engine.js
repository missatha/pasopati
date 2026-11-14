// PASOPATI — mesin sandi pasca-kuantum yang berjalan di browser.
// Port dari modul Python (qshield) dengan pustaka @noble:
//   ML-DSA-65 (FIPS 204) · ML-KEM-768 (FIPS 203) · X25519 · HKDF-SHA384 · AES-256-GCM · SHA-256
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, bytesToHex, concatBytes } from '@noble/hashes/utils.js';

const te = new TextEncoder(), td = new TextDecoder();
const CTX_HANDSHAKE = te.encode('QS-HANDSHAKE-v1');
const CTX_COMMAND = te.encode('QS-COMMAND-v1');
const CTX_LOGISTICS = te.encode('QS-LOGISTICS-v1');
const FRESHNESS = 120, HANDSHAKE_WINDOW = 120;
const GENESIS = '0'.repeat(64);

const b64e = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(s); };
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys)
  : (v && typeof v === 'object') ? Object.keys(v).sort().reduce((o, k) => (o[k] = sortKeys(v[k]), o), {}) : v;
const canonicalStr = (o) => JSON.stringify(sortKeys(o));
const canonical = (o) => te.encode(canonicalStr(o));
const now = () => Math.floor(Date.now() / 1000);
const hhmmss = () => new Date().toLocaleTimeString('id-ID', { hour12: false });
const hex = (n) => bytesToHex(randomBytes(n));
const fingerprint = (pk) => bytesToHex(sha256(pk)).slice(0, 16).toUpperCase().match(/.{4}/g).join(':');

const sign = (sk, msg, context) => ml_dsa65.sign(msg, sk, { context });
const verify = (pk, msg, sig, context) => { try { return ml_dsa65.verify(sig, msg, pk, { context }); } catch { return false; } };

class Identity {
  constructor(name, role) {
    this.name = name; this.role = role;
    const d = ml_dsa65.keygen(); this.sigPk = d.publicKey; this.sigSk = d.secretKey;
    const k = ml_kem768.keygen(); this.kemEk = k.publicKey; this.kemDk = k.secretKey;
    this.xSk = x25519.utils.randomSecretKey(); this.xPub = x25519.getPublicKey(this.xSk);
  }
  pub() { return { name: this.name, role: this.role, sigPk: this.sigPk, kemEk: this.kemEk, xPub: this.xPub }; }
}

class Session {
  constructor(key, sid, local, peer) { Object.assign(this, { key, sid, local, peer }); }
  encrypt(pt) {
    const nonce = randomBytes(12), aad = canonical({ sid: this.sid, from: this.local, to: this.peer });
    return { sid: this.sid, from: this.local, to: this.peer, nonce: b64e(nonce), ct: b64e(gcm(this.key, nonce, aad).encrypt(pt)) };
  }
  decrypt(p) { // melempar galat bila tag autentikasi tidak cocok
    const aad = canonical({ sid: p.sid, from: p.from, to: p.to });
    return gcm(this.key, b64d(p.nonce), aad).decrypt(b64d(p.ct));
  }
}

const deriveKey = (ssEcdh, ssKem, transcript) =>
  hkdf(sha384, concatBytes(ssEcdh, ssKem), te.encode('QuantumShield-hybrid-v1'), sha384(transcript), 32);

function handshakeInitiate(me, peer) {
  const t0 = performance.now();
  const eph = x25519.utils.randomSecretKey(), ephPub = x25519.getPublicKey(eph);
  const ssEcdh = x25519.getSharedSecret(eph, peer.xPub);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(peer.kemEk);
  const hs = { from: me.name, to: peer.name, eph_pub: b64e(ephPub), kem_ct: b64e(cipherText), ts: now(), nonce: hex(16) };
  const tr = canonical(hs), sig = sign(me.sigSk, tr, CTX_HANDSHAKE);
  const sid = bytesToHex(sha256(tr)).slice(0, 16);
  const stats = { ms: +(performance.now() - t0).toFixed(1), kem_ct_bytes: cipherText.length, eph_pub_bytes: ephPub.length, sig_bytes: sig.length };
  return { msg: { hs, sig: b64e(sig) }, session: new Session(deriveKey(ssEcdh, sharedSecret, tr), sid, me.name, peer.name), stats };
}

function handshakeRespond(me, msg, registry) {
  const hs = msg.hs, sender = registry.get(hs.from);
  if (!sender) throw new Error('Inisiator tidak terdaftar');
  if (hs.to !== me.name) throw new Error('Handshake bukan untuk node ini');
  if (Math.abs(now() - hs.ts) > HANDSHAKE_WINDOW) throw new Error('Handshake kedaluwarsa');
  const tr = canonical(hs);
  if (!verify(sender.sigPk, tr, b64d(msg.sig), CTX_HANDSHAKE)) throw new Error('Tanda tangan handshake tidak valid');
  const ssEcdh = x25519.getSharedSecret(me.xSk, b64d(hs.eph_pub));
  const ssKem = ml_kem768.decapsulate(b64d(hs.kem_ct), me.kemDk);
  return new Session(deriveKey(ssEcdh, ssKem, tr), bytesToHex(sha256(tr)).slice(0, 16), me.name, hs.from);
}

// ---------- perintah ----------
function createCommand(sender, to, seq, order, ts) {
  const body = { type: 'COMMAND', id: hex(6), from: sender.name, to, seq, ts: ts ?? now(), nonce: hex(16), order };
  return { body, sig: b64e(sign(sender.sigSk, canonical(body), CTX_COMMAND)) };
}

class ReplayGuard {
  constructor() { this.lastSeq = {}; this.seen = new Map(); }
  check(b) {
    if (this.seen.has(b.nonce)) return [false, 'Nonce sudah pernah dipakai (replay)'];
    const last = this.lastSeq[b.from] || 0;
    if (b.seq <= last) return [false, `Nomor urut ${b.seq} ≤ terakhir ${last}`];
    return [true, 'Nonce baru & nomor urut naik'];
  }
  commit(b) { this.seen.set(b.nonce, b.ts); this.lastSeq[b.from] = b.seq; }
}

function verifyCommand(env, me, registry, guard) {
  const b = env.body, checks = [];
  const add = (check, ok, detail) => (checks.push({ check, ok, detail }), ok);
  const sender = registry.get(b.from);
  if (!add('Identitas pengirim terdaftar', !!sender, sender ? b.from : `'${b.from}' tidak dikenal`)) return [false, checks];
  if (!add('Pengirim berwenang memberi perintah', sender.role === 'KOMANDO', `peran ${sender.role}`)) return [false, checks];
  const ok = verify(sender.sigPk, canonical(b), b64d(env.sig), CTX_COMMAND);
  if (!add('Tanda tangan ML-DSA-65 valid', ok, ok ? 'isi utuh & benar dari pengirim' : 'palsu / isi diubah')) return [false, checks];
  if (!add('Ditujukan ke satuan ini', b.to === me.name, `tujuan ${b.to}`)) return [false, checks];
  const age = now() - b.ts;
  if (!add('Perintah masih segar', age >= -5 && age <= FRESHNESS, `umur ${age} dtk (maks ${FRESHNESS})`)) return [false, checks];
  const [rok, rdet] = guard.check(b);
  if (!add('Anti-replay', rok, rdet)) return [false, checks];
  guard.commit(b);
  return [true, checks];
}

// ---------- ledger logistik ----------
const txHash = (prev, bodyJson, sig) => bytesToHex(sha256(te.encode(prev + bodyJson + sig)));
function createTx(node, jenis, item, qty, dari, ke) {
  const body = { type: 'LOGISTICS_TX', id: hex(6), signer: node.name, jenis, item, qty: parseInt(qty, 10), dari, ke, ts: now() };
  return { body, sig: b64e(sign(node.sigSk, canonical(body), CTX_LOGISTICS)) };
}
class Ledger {
  constructor(registry) { this.registry = registry; this.rows = []; }
  checkSig(body, sig) {
    const s = this.registry.get(body.signer);
    if (!s) return [false, 'penanda tangan tidak terdaftar'];
    if (s.role !== 'LOGISTIK') return [false, `peran ${s.role} tidak berwenang`];
    if (!verify(s.sigPk, canonical(body), b64d(sig), CTX_LOGISTICS)) return [false, 'tanda tangan ML-DSA tidak valid'];
    return [true, 'tanda tangan valid'];
  }
  append(env) {
    const [ok, reason] = this.checkSig(env.body, env.sig);
    if (!ok) return [false, reason];
    const prev = this.rows.length ? this.rows[this.rows.length - 1].hash : GENESIS;
    const bodyJson = canonicalStr(env.body), h = txHash(prev, bodyJson, env.sig);
    this.rows.push({ idx: this.rows.length + 1, bodyJson, sig: env.sig, prev, hash: h });
    return [true, h];
  }
  list() { return this.rows.map((r) => ({ idx: r.idx, body: JSON.parse(r.bodyJson), sig: r.sig, prev: r.prev, hash: r.hash })); }
  verifyChain() {
    let expected = GENESIS; const rows = [];
    for (const r of this.rows) {
      const problems = [];
      if (r.prev !== expected) problems.push('rantai putus (prev_hash tidak cocok)');
      if (txHash(r.prev, r.bodyJson, r.sig) !== r.hash) problems.push('hash tidak cocok (isi diubah)');
      let ok, reason; try { [ok, reason] = this.checkSig(JSON.parse(r.bodyJson), r.sig); } catch { ok = false; reason = 'data rusak'; }
      if (!ok) problems.push(reason);
      rows.push({ idx: r.idx, ok: !problems.length, problems }); expected = r.hash;
    }
    return { ok: rows.every((r) => r.ok), rows };
  }
  tamper(idx, qty, rehash) { // SIMULASI: orang dalam mengubah data langsung
    const r = this.rows.find((x) => x.idx === idx); if (!r) return false;
    const b = JSON.parse(r.bodyJson); b.qty = parseInt(qty, 10); r.bodyJson = canonicalStr(b);
    if (rehash) { let prev = r.prev; for (const x of this.rows.filter((x) => x.idx >= idx)) { x.prev = prev; x.hash = txHash(prev, x.bodyJson, x.sig); prev = x.hash; } }
    return true;
  }
  reset() { this.rows = []; }
}

// ---------- sistem ----------
const NODES = [['PUSKOM', 'KOMANDO', 'Pusat Komando'], ['SATUAN-ALFA', 'SATUAN', 'Satuan Lapangan Alfa'], ['SATUAN-BRAVO', 'SATUAN', 'Satuan Lapangan Bravo'],
  ['GUDANG-PUSAT', 'LOGISTIK', 'Gudang Logistik Pusat'], ['DEPO-WILAYAH', 'LOGISTIK', 'Depo Logistik Wilayah'], ['SERVER-LOG', 'SERVER', 'Server Ledger Logistik']];
const CHANNELS = [['PUSKOM', 'SATUAN-ALFA'], ['PUSKOM', 'SATUAN-BRAVO'], ['GUDANG-PUSAT', 'SERVER-LOG'], ['DEPO-WILAYAH', 'SERVER-LOG']];
const SAMPLES = [['GUDANG-PUSAT', 'Amunisi', 'Munisi 5.56 mm (peti)', 120, 'Gudang Pusat', 'Depo Wilayah'],
  ['GUDANG-PUSAT', 'Kendaraan', 'Truk angkut personel', 4, 'Gudang Pusat', 'Satuan Alfa'],
  ['DEPO-WILAYAH', 'Peralatan', 'Radio taktis HF', 25, 'Depo Wilayah', 'Satuan Bravo'],
  ['DEPO-WILAYAH', 'Personel', 'Ransum harian (paket)', 900, 'Depo Wilayah', 'Satuan Alfa']];
const short = (s, n = 48) => s.length <= n ? s : s.slice(0, n) + '…';

// statistik dibagi antarhalaman lewat localStorage (bila tersedia)
const STORE = 'pasopati-stats-v1';
const loadCounts = () => { try { return JSON.parse(localStorage.getItem(STORE)) || { accepted: 0, rejected: 0 }; } catch { return { accepted: 0, rejected: 0 }; } };
const saveCounts = (c) => { try { localStorage.setItem(STORE, JSON.stringify(c)); } catch { /* abaikan */ } };

class System {
  constructor() {
    this.ids = {}; this.labels = {};
    for (const [n, r, l] of NODES) { this.ids[n] = new Identity(n, r); this.labels[n] = l; }
    this.registry = new Map(Object.values(this.ids).map((i) => [i.name, i.pub()]));
    this.sessions = new Map(); this.channelInfo = {};
    for (const [a, b] of CHANNELS) this.handshake(a, b);
    this.resetCommands();
    this.ledger = new Ledger(this.registry); this.seedLedger();
    this.counts = loadCounts();
  }
  resetCommands() {
    this.guards = Object.fromEntries(Object.keys(this.ids).map((n) => [n, new ReplayGuard()]));
    this.seq = Object.fromEntries(Object.keys(this.ids).map((n) => [n, 0]));
    this.commandLog = []; this.lastLegit = {};
  }
  handshake(a, b) {
    const { msg, session, stats } = handshakeInitiate(this.ids[a], this.registry.get(b));
    const sb = handshakeRespond(this.ids[b], msg, this.registry);
    this.sessions.set(a + '>' + b, session); this.sessions.set(b + '>' + a, sb);
    const info = { from: a, to: b, sid: session.sid, algo: 'X25519 + ML-KEM-768 → HKDF-SHA384 → AES-256-GCM', auth: 'ML-DSA-65', established: hhmmss(), ...stats };
    this.channelInfo[a + '→' + b] = info; return info;
  }
  transmit(a, b, pt) { return this.sessions.get(a + '>' + b).encrypt(pt); }
  deliver(packet, receiver, senderName, label) {
    const entry = { time: hhmmss(), label, to: receiver, packet: { sid: packet.sid, nonce: packet.nonce, ct: short(packet.ct), ct_bytes: b64d(packet.ct).length } };
    let env;
    try { env = JSON.parse(td.decode(this.sessions.get(receiver + '>' + senderName).decrypt(packet))); }
    catch {
      Object.assign(entry, { accepted: false, order: null, checks: [{ check: 'Dekripsi & integritas AES-256-GCM', ok: false, detail: 'tag autentikasi gagal — paket diubah di jalan' }] });
      return this.log(entry);
    }
    const [accepted, checks] = verifyCommand(env, this.ids[receiver], this.registry, this.guards[receiver]);
    checks.unshift({ check: 'Dekripsi & integritas AES-256-GCM', ok: true, detail: 'kunci sesi hybrid cocok' });
    Object.assign(entry, { accepted, order: env.body.order, checks, claimed_from: env.body.from, seq: env.body.seq, sig_bytes: b64d(env.sig).length });
    return this.log(entry);
  }
  log(e) {
    this.commandLog.unshift(e); this.commandLog.length = Math.min(this.commandLog.length, 200);
    e.accepted ? this.counts.accepted++ : this.counts.rejected++; saveCounts(this.counts); return e;
  }
  sendCommand(to, order) {
    this.seq.PUSKOM++;
    const env = createCommand(this.ids.PUSKOM, to, this.seq.PUSKOM, order);
    const p = this.transmit('PUSKOM', to, canonical(env)); this.lastLegit[to] = { ...p };
    return this.deliver(p, to, 'PUSKOM', 'Perintah sah');
  }
  attack(kind, to = 'SATUAN-ALFA') {
    if (kind === 'replay') {
      const old = this.lastLegit[to]; if (!old) return { error: 'Belum ada perintah yang bisa disadap. Kirim perintah sah dulu.' };
      return this.deliver({ ...old }, to, 'PUSKOM', 'SERANGAN: replay perintah lama');
    }
    if (kind === 'tamper') {
      this.seq.PUSKOM++;
      const p = this.transmit('PUSKOM', to, canonical(createCommand(this.ids.PUSKOM, to, this.seq.PUSKOM, { operasi: 'Patroli', sasaran: 'Sektor 7', prioritas: 'Normal' })));
      const ct = b64d(p.ct); ct[ct.length >> 1] ^= 1; p.ct = b64e(ct);
      return this.deliver(p, to, 'PUSKOM', 'SERANGAN: ubah isi paket di jaringan');
    }
    if (kind === 'forge') {
      const fake = new Identity('PUSKOM', 'KOMANDO');
      const env = createCommand(fake, to, this.seq.PUSKOM + 1, { operasi: 'Tarik mundur seluruh pasukan', sasaran: 'Semua sektor', prioritas: 'Kilat' });
      return this.deliver(this.transmit('PUSKOM', to, canonical(env)), to, 'PUSKOM', 'SERANGAN: pemalsuan identitas Pusat Komando');
    }
    if (kind === 'expired') {
      this.seq.PUSKOM++;
      const env = createCommand(this.ids.PUSKOM, to, this.seq.PUSKOM, { operasi: 'Serbu', sasaran: 'Titik B', prioritas: 'Kilat' }, now() - 3600);
      return this.deliver(this.transmit('PUSKOM', to, canonical(env)), to, 'PUSKOM', 'SERANGAN: perintah kedaluwarsa (ditahan 1 jam)');
    }
    if (kind === 'misroute') {
      const other = to === 'SATUAN-ALFA' ? 'SATUAN-BRAVO' : 'SATUAN-ALFA'; this.seq.PUSKOM++;
      const env = createCommand(this.ids.PUSKOM, other, this.seq.PUSKOM, { operasi: 'Bergerak', sasaran: 'Titik C', prioritas: 'Segera' });
      return this.deliver(this.transmit('PUSKOM', to, canonical(env)), to, 'PUSKOM', `SERANGAN: perintah untuk ${other} dialihkan ke ${to}`);
    }
    return { error: 'jenis serangan tidak dikenal' };
  }
  submitTx(node, jenis, item, qty, dari, ke) {
    const env = createTx(this.ids[node], jenis, item, qty, dari, ke);
    const p = this.transmit(node, 'SERVER-LOG', canonical(env));
    const received = JSON.parse(td.decode(this.sessions.get('SERVER-LOG>' + node).decrypt(p)));
    const [ok, info] = this.ledger.append(received);
    return { ok, info, ct_bytes: b64d(p.ct).length, sid: p.sid };
  }
  submitForgedTx() {
    const fake = new Identity('GUDANG-PUSAT', 'LOGISTIK');
    const [ok, info] = this.ledger.append(createTx(fake, 'Amunisi', 'Munisi 5.56 mm', 50000, 'Gudang Pusat', 'Tidak diketahui'));
    return { ok, info };
  }
  seedLedger() { if (!this.ledger.rows.length) for (const s of SAMPLES) this.submitTx(...s); }
  nodes() { return Object.values(this.ids).map((i) => ({ name: i.name, role: i.role, label: this.labels[i.name], fp: fingerprint(i.sigPk), sig_pk_bytes: i.sigPk.length, kem_ek_bytes: i.kemEk.length })); }
  stats() { return { accepted: this.counts.accepted, rejected: this.counts.rejected, ledger: this.ledger.rows.length, nodes: Object.keys(this.ids).length, channels: Object.keys(this.channelInfo).length }; }
  benchmark(n = 5) {
    const t = (fn) => { const xs = []; for (let i = 0; i < n; i++) { const s = performance.now(); fn(); xs.push(performance.now() - s); } xs.sort((a, b) => a - b); return +xs[xs.length >> 1].toFixed(2); };
    const msg = new Uint8Array(512).fill(120);
    const d = ml_dsa65.keygen(), sig = ml_dsa65.sign(msg, d.secretKey), k = ml_kem768.keygen(), ct = ml_kem768.encapsulate(k.publicKey).cipherText;
    const ec = p256.utils.randomSecretKey(), ecSig = p256.sign(msg, ec);
    return [
      { op: 'ML-DSA-65 keygen', ms: t(() => ml_dsa65.keygen()) },
      { op: 'ML-DSA-65 sign', ms: t(() => ml_dsa65.sign(msg, d.secretKey)), size: `sig ${sig.length} B` },
      { op: 'ML-DSA-65 verify', ms: t(() => ml_dsa65.verify(sig, msg, d.publicKey)), size: `pk ${d.publicKey.length} B` },
      { op: 'ML-KEM-768 keygen', ms: t(() => ml_kem768.keygen()), size: `ek ${k.publicKey.length} B` },
      { op: 'ML-KEM-768 encaps', ms: t(() => ml_kem768.encapsulate(k.publicKey)), size: `ct ${ct.length} B` },
      { op: 'ML-KEM-768 decaps', ms: t(() => ml_kem768.decapsulate(ct, k.secretKey)) },
      { op: 'ECDSA P-256 sign (klasik, pembanding)', ms: t(() => p256.sign(msg, ec)), size: `sig ${ecSig.length} B` },
    ];
  }
}

// ---------- API tiruan: bentuk JSON sama dengan server Flask ----------
let sys = null;
const S = () => (sys ??= new System());
function call(path, body = {}) {
  const s = S();
  switch (path) {
    case '/api/state': return { nodes: s.nodes(), channels: Object.values(s.channelInfo), commands: s.commandLog.slice(0, 30), ledger: s.ledger.list() };
    case '/api/stats': return s.stats();
    case '/api/benchmark': return s.benchmark();
    case '/api/handshake': return s.handshake(body.from, body.to);
    case '/api/command': return s.sendCommand(body.to || 'SATUAN-ALFA', { operasi: body.operasi || '', sasaran: body.sasaran || '', prioritas: body.prioritas || 'Normal' });
    case '/api/logistics/tx': return s.submitTx(body.node, body.jenis, body.item, body.qty, body.dari, body.ke);
    case '/api/logistics/forge': return s.submitForgedTx();
    case '/api/logistics/verify': return s.ledger.verifyChain();
    case '/api/logistics/tamper': {
      const idx = parseInt(body.idx, 10), qty = parseInt(body.qty, 10);
      if (Number.isNaN(idx) || Number.isNaN(qty)) return { error: 'Nomor catatan dan jumlah harus angka.' };
      if (!s.ledger.tamper(idx, qty, !!body.rehash)) return { error: `Catatan #${idx} tidak ada. Pilih nomor yang ada di tabel.` };
      return s.ledger.verifyChain();
    }
    case '/api/logistics/reset': s.ledger.reset(); s.seedLedger(); return { ok: true };
    case '/api/reset': s.resetCommands(); s.ledger.reset(); s.seedLedger(); s.counts = { accepted: 0, rejected: 0 }; saveCounts(s.counts); return { ok: true };
  }
  if (path.startsWith('/api/attack/')) return s.attack(path.slice(12), body.to || 'SATUAN-ALFA');
  return { error: 'tidak dikenal: ' + path };
}

// Arahkan fetch('/api/...') ke mesin lokal, sehingga skrip halaman tidak perlu diubah.
const realFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : input.url;
  const m = url.match(/(?:^|\/)(api\/[^?#]*)/);
  if (!m) return realFetch(input, init);
  await new Promise((r) => setTimeout(r, 0)); // beri waktu UI menggambar status "memproses"
  const body = init.body ? JSON.parse(init.body) : {};
  return new Response(JSON.stringify(call('/' + m[1], body)), { status: 200, headers: { 'Content-Type': 'application/json' } });
};
window.PASOPATI = { call, version: '0.1.0-browser' };
