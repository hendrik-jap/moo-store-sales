// Merges the two encrypted pages (store sales + 2027 EBITDA simulator) into ONE
// encrypted payload behind ONE password. Plaintext never touches disk or git.
//
// Usage (Node 18+), from the repo root:
//   read -rs -p "Old store-sales password: " SALES_PW; echo
//   read -rs -p "Old simulator password: "  SCENARIO_PW; echo
//   read -rs -p "New shared password: "     NEW_PW; echo
//   export SALES_PW SCENARIO_PW NEW_PW
//   node tools/build-integrated.mjs
//
// Optional: --sales <file> --scenario <file> to decrypt other copies of the old pages.
// Default sources are the pre-integration pages at git commit 516fadf.
import { webcrypto as c } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const OLD_REF = '516fadf';
const arg = (n) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : null; };
const need = (n) => { const v = process.env[n]; if (!v) { console.error(`Missing env var ${n}`); process.exit(1); } return v; };
const load = (flag, path) => { const f = arg(flag); return f ? readFileSync(f, 'utf8') : execFileSync('git', ['show', `${OLD_REF}:${path}`], { encoding: 'utf8', maxBuffer: 1 << 28 }); };

const b64 = (u8) => Buffer.from(u8).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const key = async (pw, salt, use) => {
  const k0 = await c.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return c.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, k0, { name: 'AES-GCM', length: 256 }, false, [use]);
};
async function decryptPage(html, pw, label) {
  const m = html.match(/const S="([^"]+)",I="([^"]+)",C="([^"]+)"/);
  if (!m) throw new Error(`${label}: encrypted payload not found`);
  try {
    const k = await key(pw, unb64(m[1]), 'decrypt');
    return new TextDecoder().decode(await c.subtle.decrypt({ name: 'AES-GCM', iv: unb64(m[2]) }, k, unb64(m[3])));
  } catch { throw new Error(`${label}: wrong password`); }
}
async function encrypt(text, pw) {
  const salt = c.getRandomValues(new Uint8Array(16)), iv = c.getRandomValues(new Uint8Array(12));
  const k = await key(pw, salt, 'encrypt');
  const ct = new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(text)));
  return { S: b64(salt), I: b64(iv), C: b64(ct) };
}
const jsStr = (s) => JSON.stringify(s).replace(/</g, '\\u003c').split(String.fromCharCode(8232)).join('\\u2028').split(String.fromCharCode(8233)).join('\\u2029');

const SHELL = (sales, scenario) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Kacamatamoo</title>
<style>:root{color-scheme:light dark;--bg:#fffaf0;--fg:#1B1D4D;--ln:#d9d3c4;--on-bg:#1B1D4D;--on-fg:#fffaf0}
@media(prefers-color-scheme:dark){:root{--bg:#1B1D4D;--fg:#fffaf0;--ln:#2c3070;--on-bg:#fffaf0;--on-fg:#1B1D4D}}
html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:14px/1 Poppins,system-ui,sans-serif}
header{position:fixed;inset:0 0 auto 0;height:52px;display:flex;align-items:center;gap:12px;padding:0 16px;border-bottom:1px solid var(--ln);background:var(--bg);box-sizing:border-box}
header b{font-weight:600;letter-spacing:.2px;white-space:nowrap}
nav{display:flex;gap:2px;padding:3px;border:1px solid var(--ln);border-radius:999px;margin-left:auto;max-width:100%;overflow-x:auto}
nav button{font:inherit;padding:8px 14px;border:0;border-radius:999px;background:transparent;color:var(--fg);cursor:pointer;white-space:nowrap}
nav button[aria-selected=true]{background:var(--on-bg);color:var(--on-fg)}
iframe{position:fixed;top:52px;left:0;width:100%;height:calc(100% - 52px);border:0;background:var(--bg);display:none}
iframe.on{display:block}
@media(max-width:560px){header b{display:none}nav{margin-left:0;width:100%}nav button{flex:1;padding:8px 10px}}</style></head>
<body><header><b>Kacamatamoo</b><nav role="tablist"><button role="tab" data-t="sales">Store sales</button><button role="tab" data-t="scenario">2027 EBITDA simulator</button></nav></header>
<iframe id="sales" title="Store sales"></iframe><iframe id="scenario" title="2027 EBITDA simulator"></iframe>
<script>
var D={sales:${jsStr(sales)},scenario:${jsStr(scenario)}};
function show(t){if(!D[t])t='sales';var f=document.getElementById(t);if(!f.getAttribute('data-l')){f.srcdoc=D[t];f.setAttribute('data-l','1')}
['sales','scenario'].forEach(function(k){document.getElementById(k).className=k===t?'on':'';});
document.querySelectorAll('nav button').forEach(function(b){b.setAttribute('aria-selected',b.getAttribute('data-t')===t)});
if(location.hash!=='#'+t)history.replaceState(null,'','#'+t)}
document.querySelectorAll('nav button').forEach(function(b){b.onclick=function(){show(b.getAttribute('data-t'))}});
addEventListener('hashchange',function(){show(location.hash.slice(1))});
show(location.hash.slice(1));
</script></body></html>`;

const GATE = (p) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Kacamatamoo</title>
<style>:root{color-scheme:light dark;--bg:#f6faf9;--fg:#0f2423;--card:#fff;--ln:#d6e4e2;--ac:#078282}@media(prefers-color-scheme:dark){:root{--bg:#0b1716;--fg:#e6f2f1;--card:#112321;--ln:#24403d;--ac:#12a3a0}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px system-ui,sans-serif;padding:16px;box-sizing:border-box}
form{background:var(--card);border:1px solid var(--ln);border-radius:8px;padding:24px;width:100%;max-width:340px;display:flex;flex-direction:column;gap:12px}
h1{font-size:18px;margin:0}input,button{font:inherit;padding:10px;border-radius:6px;border:1px solid var(--ln);background:var(--bg);color:var(--fg)}button{background:var(--ac);color:#fff;border:0;cursor:pointer}#e{color:#b3261e;margin:0;min-height:1em}</style></head>
<body><form id="f"><h1>Kacamatamoo store sales and 2027 EBITDA simulator</h1><label for="p">Password</label><input id="p" type="password" autocomplete="current-password" autofocus><button>Unlock</button><p id="e"></p></form>
<script>
const S="${p.S}",I="${p.I}",C="${p.C}";
const d=s=>Uint8Array.from(atob(s),x=>x.charCodeAt(0));
document.getElementById('f').onsubmit=async e=>{e.preventDefault();const m=document.getElementById('e');m.textContent='Decrypting...';
try{const k0=await crypto.subtle.importKey('raw',new TextEncoder().encode(document.getElementById('p').value),'PBKDF2',false,['deriveKey']);
const k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:d(S),iterations:600000,hash:'SHA-256'},k0,{name:'AES-GCM',length:256},false,['decrypt']);
const t=new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:d(I)},k,d(C)));
document.open();document.write(t);document.close()}catch(x){m.textContent='Wrong password.'}};
</script></body></html>`;

const STUB = `<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Kacamatamoo</title><meta http-equiv="refresh" content="0;url=/#scenario"></head><body><script>location.replace('/#scenario')</script></body></html>`;

try {
const sales = await decryptPage(load('sales', 'index.html'), need('SALES_PW'), 'Store sales page');
const scenario = await decryptPage(load('scenario', 'scenario/index.html'), need('SCENARIO_PW'), 'Simulator page');
const payload = await encrypt(SHELL(sales, scenario), need('NEW_PW'));
const out = arg('out') || '.';
mkdirSync(`${out}/scenario`, { recursive: true });
writeFileSync(`${out}/index.html`, GATE(payload));
writeFileSync(`${out}/scenario/index.html`, STUB);
console.log(`Wrote ${out}/index.html (${(GATE(payload).length / 1024).toFixed(0)} KB) and ${out}/scenario/index.html (redirect to /#scenario)`);
} catch (e) { console.error('Build failed: ' + e.message); process.exit(1); }
