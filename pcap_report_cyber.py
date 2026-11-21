# -*- coding: utf-8 -*-
"""
pcap_report_cyber — گزارش «کنسول سایبری» (HTML تک‌فایل، ۱۰۰٪ آفلاین)
======================================================================
• ۸ تم دارک‌سایبری + ۴ متریال (Glass / Solid / Hologram / Terminal) + افکت‌های انتخابی (گرید، اسکن‌لاین، درخشش، باران ماتریکس)
• هر پروتکل: کلیک ← همه‌ی رویدادها (HTTP: تراکنش‌ها، فایل‌های دانلود/آپلود با نام اصلی، هدرها؛ DNS: دامنه‌ها؛ TLS: SNI/JA3 ...)
• هر مسیر (میزبان↔میزبان): کلیک ← جریان‌ها، پروتکل‌ها، رویدادها و فایل‌ها
• «مرورگر ZIP»: فهرست دقیق فایل‌های استخراج‌شده مثل یک ZIP واقعی (درخت پوشه‌ها، اندازه، CRC، هش، پیش‌نمایش امن)
• همه‌ی داده‌های بسته با textContent رندر می‌شوند (XSS-safe)

Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer · MIT
"""
from __future__ import annotations

import json
import re
import os
import time

import app_meta as META
import pcap_i18n as I18N
import pcap_themes as TH

CSS = r"""
html[data-lang=en] .l-fa,html[data-lang=fa] .l-en{display:none}
*{box-sizing:border-box}
html{--fs:14px;--r:14px;--gap:14px;--glow:1;--blur:18px}
body{margin:0;background:var(--bg);color:var(--ink);font:var(--fs)/1.75 'Vazirmatn','Segoe UI Variable','Segoe UI',system-ui,Tahoma,sans-serif;min-height:100vh;overflow-x:hidden}
code,pre,.mono,.ltr{font-family:'Cascadia Mono','JetBrains Mono',Consolas,'DejaVu Sans Mono',monospace}
.ltr{direction:ltr;unicode-bidi:plaintext;text-align:left}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
::selection{background:var(--acc);color:var(--bg)}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--acc) 35%,transparent);border-radius:8px}::-webkit-scrollbar-track{background:transparent}
/* ---------- background layers */
#bg-grid,#bg-scan,#rain{position:fixed;inset:0;pointer-events:none;z-index:0}
#bg-grid{background:
 radial-gradient(60vmax 40vmax at 8% -10%,color-mix(in srgb,var(--acc3) 22%,transparent),transparent 60%),
 radial-gradient(55vmax 40vmax at 96% 0%,color-mix(in srgb,var(--acc) 16%,transparent),transparent 62%),
 radial-gradient(50vmax 40vmax at 70% 110%,color-mix(in srgb,var(--acc2) 14%,transparent),transparent 60%)}
html[data-grid="1"] #bg-grid{background-image:
 linear-gradient(color-mix(in srgb,var(--acc) 9%,transparent) 1px,transparent 1px),
 linear-gradient(90deg,color-mix(in srgb,var(--acc) 9%,transparent) 1px,transparent 1px),
 radial-gradient(60vmax 40vmax at 8% -10%,color-mix(in srgb,var(--acc3) 22%,transparent),transparent 60%),
 radial-gradient(55vmax 40vmax at 96% 0%,color-mix(in srgb,var(--acc) 16%,transparent),transparent 62%),
 radial-gradient(50vmax 40vmax at 70% 110%,color-mix(in srgb,var(--acc2) 14%,transparent),transparent 60%);
 background-size:44px 44px,44px 44px,auto,auto,auto;mask-image:linear-gradient(#000 55%,transparent)}
#bg-scan{display:none;background:repeating-linear-gradient(0deg,rgba(0,0,0,.18) 0 1px,transparent 1px 3px);mix-blend-mode:multiply;z-index:60}
html[data-scan="1"] #bg-scan{display:block}
#rain{display:none;opacity:.35}html[data-rain="1"] #rain{display:block}
.app{position:relative;z-index:1;display:grid;grid-template-columns:230px 1fr;gap:var(--gap);max-width:1700px;margin:auto;padding:var(--gap)}
@media(max-width:980px){.app{grid-template-columns:1fr}}
/* ---------- materials */
.panel,.card,.nav,.hdr,.modal-box,.drawer{background:linear-gradient(150deg,color-mix(in srgb,var(--panel2) 92%,transparent),color-mix(in srgb,var(--panel) 94%,transparent));border:1px solid var(--line);border-radius:var(--r);box-shadow:0 18px 50px -22px #000}
html[data-material="glass"] .panel,html[data-material="glass"] .card,html[data-material="glass"] .nav,html[data-material="glass"] .hdr,html[data-material="glass"] .modal-box,html[data-material="glass"] .drawer{
 background:linear-gradient(150deg,color-mix(in srgb,var(--ink) 7%,transparent),color-mix(in srgb,var(--ink) 2.5%,transparent));backdrop-filter:blur(var(--blur)) saturate(160%);-webkit-backdrop-filter:blur(var(--blur)) saturate(160%);border-color:color-mix(in srgb,var(--ink) 15%,transparent);box-shadow:inset 0 1px 0 color-mix(in srgb,var(--ink) 18%,transparent),0 22px 60px -24px #000}
html[data-material="solid"] .panel,html[data-material="solid"] .card,html[data-material="solid"] .nav,html[data-material="solid"] .hdr{background:var(--panel);box-shadow:none}
html[data-material="hologram"] .panel,html[data-material="hologram"] .card,html[data-material="hologram"] .nav,html[data-material="hologram"] .hdr,html[data-material="hologram"] .modal-box,html[data-material="hologram"] .drawer{
 background:linear-gradient(160deg,color-mix(in srgb,var(--acc) 9%,transparent),color-mix(in srgb,var(--acc3) 4%,transparent));border:1px solid color-mix(in srgb,var(--acc) 55%,transparent);
 box-shadow:0 0 calc(18px*var(--glow)) color-mix(in srgb,var(--acc) 28%,transparent),inset 0 0 26px color-mix(in srgb,var(--acc) 7%,transparent);clip-path:polygon(0 12px,12px 0,calc(100% - 12px) 0,100% 12px,100% calc(100% - 12px),calc(100% - 12px) 100%,12px 100%,0 calc(100% - 12px))}
html[data-material="terminal"]{--r:2px}
html[data-material="terminal"] body{font-family:'Cascadia Mono','JetBrains Mono',Consolas,'DejaVu Sans Mono',monospace}
html[data-material="terminal"] .panel,html[data-material="terminal"] .card,html[data-material="terminal"] .nav,html[data-material="terminal"] .hdr,html[data-material="terminal"] .modal-box,html[data-material="terminal"] .drawer{background:var(--bg2);border:1px solid var(--acc);box-shadow:0 0 calc(10px*var(--glow)) color-mix(in srgb,var(--acc) 30%,transparent)}
html[data-glow="1"] h1,html[data-glow="1"] .glow{text-shadow:0 0 14px color-mix(in srgb,var(--acc) 70%,transparent)}
html[data-density="compact"]{--gap:8px;--fs:12.5px}html[data-density="compact"] td,html[data-density="compact"] th{padding:3px 8px!important}
html[data-anim="0"] *{animation:none!important;transition:none!important}
/* ---------- header / nav */
.hdr{grid-column:1/-1;display:flex;gap:18px;align-items:center;flex-wrap:wrap;padding:14px 20px;position:relative;overflow:hidden}
.hdr:before{content:"";position:absolute;inset:0;background:linear-gradient(100deg,transparent 40%,color-mix(in srgb,var(--acc) 14%,transparent) 50%,transparent 60%);transform:translateX(-100%);animation:sweep 7s infinite}
@keyframes sweep{to{transform:translateX(100%)}}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;font-size:24px;background:linear-gradient(135deg,var(--acc),var(--acc2));color:var(--bg);box-shadow:0 0 22px color-mix(in srgb,var(--acc) 55%,transparent)}
h1{margin:0;font-size:19px;letter-spacing:.02em}.sub{color:var(--mut);font-size:12px}
.hdr .fill{flex:1}
.chip{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:99px;border:1px solid var(--line);background:color-mix(in srgb,var(--ink) 4%,transparent);font-size:12px;color:var(--mut);white-space:nowrap}
.chip.acc{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 50%,transparent)}.chip.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 55%,transparent)}.chip.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 50%,transparent)}.chip.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 50%,transparent)}
.btn{cursor:pointer;font:inherit;font-weight:700;font-size:12.5px;color:var(--ink);background:color-mix(in srgb,var(--ink) 6%,transparent);border:1px solid var(--line);border-radius:10px;padding:6px 14px;transition:.15s}
.btn:hover{border-color:var(--acc);color:var(--acc);box-shadow:0 0 16px color-mix(in srgb,var(--acc) 30%,transparent)}
.btn.pri{background:linear-gradient(135deg,var(--acc),var(--acc3));color:var(--bg);border-color:transparent}.btn.pri:hover{color:var(--bg);filter:brightness(1.12)}
.btn.on{border-color:var(--acc);color:var(--acc);background:color-mix(in srgb,var(--acc) 12%,transparent)}
.nav{padding:10px;display:flex;flex-direction:column;gap:4px;position:sticky;top:var(--gap);align-self:start;max-height:calc(100vh - 2*var(--gap));overflow:auto}
@media(max-width:980px){.nav{flex-direction:row;overflow-x:auto;position:static}}
.nav button{all:unset;cursor:pointer;display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;color:var(--mut);font-weight:700;white-space:nowrap;border:1px solid transparent}
.nav button:hover{color:var(--ink);background:color-mix(in srgb,var(--ink) 6%,transparent)}
.nav button.on{color:var(--acc);background:color-mix(in srgb,var(--acc) 12%,transparent);border-color:color-mix(in srgb,var(--acc) 40%,transparent);box-shadow:0 0 18px color-mix(in srgb,var(--acc) 18%,transparent)}
.nav .badge{margin-inline-start:auto;font-size:11px;background:var(--acc);color:var(--bg);border-radius:99px;padding:0 7px;font-weight:800}
.nav .sep{height:1px;background:var(--line);margin:6px 4px}
main{min-width:0;display:flex;flex-direction:column;gap:var(--gap)}
.view{display:none;flex-direction:column;gap:var(--gap)}.view.on{display:flex;animation:fade .25s}
@keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
h2{margin:6px 0 0;font-size:17px;display:flex;align-items:center;gap:10px}h2:before{content:"";width:5px;height:20px;border-radius:3px;background:linear-gradient(var(--acc),var(--acc2));box-shadow:0 0 12px var(--acc)}
h3{margin:0 0 8px;font-size:14px;color:var(--acc)}
.card,.panel{padding:14px 16px}
.grid{display:grid;gap:var(--gap)}.g2{grid-template-columns:repeat(auto-fit,minmax(360px,1fr))}.g3{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}.g4{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.stat .v{font-size:25px;font-weight:800;color:var(--ink);line-height:1.2}.stat .l{color:var(--mut);font-size:12px}.stat .v.acc{color:var(--acc)}
.muted{color:var(--mut)}.dim{color:var(--dim)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
input[type=search],input[type=text],select{font:inherit;color:var(--ink);background:color-mix(in srgb,var(--bg) 70%,transparent);border:1px solid var(--line);border-radius:10px;padding:6px 12px;min-width:200px}
input:focus,select:focus{outline:none;border-color:var(--acc);box-shadow:0 0 14px color-mix(in srgb,var(--acc) 30%,transparent)}
/* ---------- tables */
.tw{overflow:auto;border:1px solid var(--line);border-radius:12px;max-height:68vh}
table{width:100%;border-collapse:collapse;font-size:12.8px}
th{position:sticky;top:0;background:color-mix(in srgb,var(--panel2) 96%,var(--bg));color:var(--mut);font-weight:700;text-align:start;padding:7px 10px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap;z-index:2}
th:hover{color:var(--acc)}
td{padding:6px 10px;border-bottom:1px solid color-mix(in srgb,var(--line) 55%,transparent);vertical-align:top;max-width:520px;overflow-wrap:break-word;word-break:normal}
td.mono,td.nw{white-space:nowrap}
tr.click{cursor:pointer}tr.click:hover td{background:color-mix(in srgb,var(--acc) 9%,transparent)}
tr.x1 td:first-child{box-shadow:inset 3px 0 var(--warn)}tr.x2 td:first-child{box-shadow:inset 3px 0 var(--bad)}
.st2{color:var(--ok)}.st3{color:var(--acc)}.st4{color:var(--warn)}.st5{color:var(--bad)}
.sev{display:inline-block;padding:0 9px;border-radius:6px;font-weight:800;font-size:11.5px;color:#06070d}
.pill{display:inline-block;border:1px solid var(--line);border-radius:8px;padding:0 8px;margin:2px;font-size:12px;background:color-mix(in srgb,var(--bg) 60%,transparent);direction:ltr}
.tag{display:inline-block;padding:0 7px;border-radius:6px;font-size:11px;font-weight:700;margin:1px;border:1px solid var(--line);color:var(--mut)}
.tag.bad{color:var(--bad);border-color:var(--bad)}.tag.warn{color:var(--warn);border-color:var(--warn)}.tag.ok{color:var(--ok);border-color:var(--ok)}.tag.acc{color:var(--acc);border-color:var(--acc)}
pre{margin:6px 0;background:color-mix(in srgb,var(--bg) 85%,#000);border:1px solid var(--line);border-radius:10px;padding:10px 12px;overflow:auto;white-space:pre-wrap;word-break:break-all;direction:ltr;text-align:left;font-size:12px;color:var(--acc);max-height:360px}
.bar{height:7px;border-radius:5px;background:linear-gradient(90deg,var(--acc),var(--acc2));box-shadow:0 0 10px color-mix(in srgb,var(--acc) 40%,transparent)}.barbg{background:color-mix(in srgb,var(--bg) 80%,#000);border-radius:5px}
/* ---------- protocol browser */
.split{display:grid;grid-template-columns:300px 1fr;gap:var(--gap);align-items:start}@media(max-width:1100px){.split{grid-template-columns:1fr}}
.plist{display:flex;flex-direction:column;gap:8px;max-height:78vh;overflow:auto;padding:2px}
.pcard{all:unset;cursor:pointer;display:block;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:color-mix(in srgb,var(--ink) 3%,transparent);transition:.15s}
.pcard:hover{border-color:var(--acc)}.pcard.on{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 12%,transparent);box-shadow:0 0 20px color-mix(in srgb,var(--acc) 20%,transparent)}
.pcard .top{display:flex;align-items:center;gap:8px;font-weight:800}.pcard .ic{font-size:18px}.pcard .meta{display:flex;gap:10px;color:var(--mut);font-size:11.5px;margin-top:3px;flex-wrap:wrap}
.tabs{display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:8px}
.tabs button{all:unset;cursor:pointer;padding:5px 14px;border-radius:9px;font-weight:700;color:var(--mut);border:1px solid transparent}
.tabs button:hover{color:var(--ink)}.tabs button.on{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 45%,transparent);background:color-mix(in srgb,var(--acc) 10%,transparent)}
.story{display:flex;flex-direction:column;gap:8px}.story .it{padding:10px 14px;border-inline-start:3px solid var(--acc);background:color-mix(in srgb,var(--acc) 6%,transparent);border-radius:8px}
/* ---------- files / zip explorer */
.zipbar{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.zipico{width:54px;height:54px;border-radius:12px;display:grid;place-items:center;font-size:28px;background:linear-gradient(135deg,var(--acc3),var(--acc));color:var(--bg)}
.tree details{margin-inline-start:14px;border-inline-start:1px dashed var(--line);padding-inline-start:8px}
.tree summary{cursor:pointer;padding:3px 6px;border-radius:6px;font-weight:700;list-style:none}.tree summary::-webkit-details-marker{display:none}
.tree summary:before{content:"▸ ";color:var(--acc)}.tree details[open]>summary:before{content:"▾ "}
.tree summary:hover{background:color-mix(in srgb,var(--acc) 8%,transparent)}
.frow{display:grid;grid-template-columns:minmax(160px,3fr) 80px 90px 150px 1fr;gap:10px;align-items:center;padding:4px 8px;border-radius:8px;cursor:pointer;font-size:12.5px}
.frow:hover{background:color-mix(in srgb,var(--acc) 9%,transparent)}.frow .nm{overflow-wrap:anywhere}
.fhead{color:var(--mut);font-weight:700;font-size:11.5px;cursor:default}.fhead:hover{background:none}
@media(max-width:900px){.frow{grid-template-columns:1fr 70px}.frow>:nth-child(n+3){display:none}}
/* ---------- modal / drawer */
.ov{position:fixed;inset:0;background:rgba(0,0,0,.62);z-index:80;display:none;align-items:flex-start;justify-content:center;padding:4vh 14px;overflow:auto}.ov.on{display:flex}
.modal-box{width:min(1100px,100%);padding:18px 20px;position:relative}
.x{position:absolute;inset-inline-end:12px;top:10px}
.kvg{display:grid;grid-template-columns:150px 1fr;gap:4px 14px;font-size:12.8px}.kvg dt{color:var(--mut)}.kvg dd{margin:0;overflow-wrap:anywhere}
.drawer{position:fixed;inset-block:var(--gap);inset-inline-start:var(--gap);width:min(380px,calc(100vw - 2*var(--gap)));z-index:90;padding:16px;overflow:auto;display:none}.drawer.on{display:block;animation:fade .2s}
.swatches{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.sw{all:unset;cursor:pointer;border:1px solid var(--line);border-radius:12px;padding:8px;display:flex;flex-direction:column;gap:6px;font-weight:700;font-size:12px}
.sw:hover,.sw.on{border-color:var(--acc);box-shadow:0 0 16px color-mix(in srgb,var(--acc) 30%,transparent)}.sw i{display:flex;height:16px;border-radius:5px;overflow:hidden}.sw i b{flex:1}
.opt{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px dashed var(--line)}
.toast{position:fixed;bottom:18px;inset-inline-start:50%;transform:translateX(-50%);background:var(--acc);color:var(--bg);padding:8px 18px;border-radius:99px;font-weight:800;z-index:120;display:none}
.kc{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.kcn{border:1px solid var(--line);border-radius:12px;padding:10px;text-align:center}.kcn.on{border-color:var(--bad);box-shadow:0 0 18px color-mix(in srgb,var(--bad) 35%,transparent)}
.pyr{display:flex;flex-direction:column;align-items:center;gap:6px}.pyr div{border-radius:9px;padding:6px 12px;text-align:center;color:var(--ink);border:1px solid var(--line);background:color-mix(in srgb,var(--acc) 10%,transparent)}
.verdict{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.verdict .big{font-size:50px}
details.f{border:1px solid var(--line);border-radius:12px;margin:8px 0;background:color-mix(in srgb,var(--ink) 3%,transparent)}details.f>summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
details.f>summary::-webkit-details-marker{display:none}details.f .bd{padding:4px 16px 14px;border-top:1px dashed var(--line)}
.plain{display:grid;gap:8px;margin:8px 0}.plain div{padding:8px 12px;border-radius:8px;border-inline-start:4px solid var(--acc);background:color-mix(in srgb,var(--ink) 4%,transparent)}.plain .w{border-color:var(--acc)}.plain .y{border-color:var(--warn)}.plain .t{border-color:var(--ok)}
body.simple .tech{display:none}
.empty{padding:26px;text-align:center;color:var(--dim)}
@media print{html{--bg:#fff}#bg-grid,#bg-scan,#rain,.nav,.drawer,.btn,.hdr:before{display:none!important}.app{display:block}.view{display:flex!important;break-inside:avoid}.panel,.card{background:#fff!important;color:#000!important;box-shadow:none!important;clip-path:none!important;backdrop-filter:none!important}body{color:#000}}
"""

JS_SRC = r"""
'use strict';
const D=JSON.parse(document.getElementById('data').textContent);
const $=(s,r)=>(r||document).querySelector(s);
const UI=D.ui||{};let LANGX=D.meta.lang||'en';try{LANGX=localStorage.getItem('pcaplang')||LANGX}catch(e){}
{const hm=(location.hash.match(/lang=(en|fa)/)||[])[1];if(hm)LANGX=hm}
const T=s=>{if(LANGX==='fa'||typeof s!=='string')return s;const v=UI[s];if(v!==undefined)return v;
  const m=s.match(/^([^\d]*[^\d\s])(\s*[\d][\s\S]*)$/);if(m&&UI[m[1]]!==undefined)return UI[m[1]]+m[2];
  const m2=s.match(/^([\s\S]*?)(\s+)$/);if(m2&&UI[m2[1]]!==undefined)return UI[m2[1]]+m2[2];return s};
const FL=(o,k)=>o[k+'_'+LANGX]||o[k+'_en']||o[k];
function el(tag,a){const e=document.createElement(tag);if(a)for(const k in a){const v=a[k];if(v==null||v===false)continue;
 if(k==='class')e.className=v;else if(k==='text')e.textContent=T(v);else if(k==='style')e.style.cssText=v;else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),v);else e.setAttribute(k,v===true?'':v)}
 for(let i=2;i<arguments.length;i++){let c=arguments[i];if(c==null||c===false)continue;if(Array.isArray(c)){c.forEach(x=>x!=null&&x!==false&&e.append(x.nodeType?x:document.createTextNode(T(String(x)))));continue}e.append(c.nodeType?c:document.createTextNode(T(String(c))))}return e}
const LI=s=>'\u2066'+s+'\u2069';
const num=n=>(n==null?'—':Number(n).toLocaleString('en-US'));
const hb=n=>{n=Number(n)||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<4){n/=1024;i++}return LI((i?n.toFixed(n<10?2:1):n)+' '+u[i])};
const tsf=t=>{if(!t)return '—';const d=new Date(t*1000);return LI(d.toISOString().replace('T',' ').slice(0,19))};
const dur=s=>{s=Number(s)||0;return LI(s<1?(s*1000).toFixed(0)+' ms':s<120?s.toFixed(1)+' s':(s/60).toFixed(1)+' min')};
const PM={HTTP:['🌐','وب بدون رمزنگاری'],TLS:['🔐','TLS/HTTPS رمزنگاری‌شده'],DNS:['🧭','نام‌یابی دامنه'],FTP:['📁','انتقال فایل'],SMTP:['✉️','ارسال ایمیل'],POP3:['📬','دریافت ایمیل'],IMAP:['📬','ایمیل IMAP'],SMB:['🗄️','اشتراک فایل ویندوز'],SSH:['🖥️','شل امن'],RDP:['🖱️','دسکتاپ راه‌دور'],Telnet:['⌨️','ترمینال بدون رمز'],DHCP:['📡','اختصاص IP'],ICMP:['📶','Ping و خطاها'],ARP:['🔗','نگاشت IP↔MAC'],TFTP:['💾','FTP ساده'],SNMP:['📊','مدیریت شبکه'],NTP:['🕒','همگام‌سازی ساعت'],Kerberos:['🎫','احراز هویت دامنه'],LDAP:['📚','دایرکتوری'],IRC:['💬','چت IRC'],VNC:['🖼️','دسکتاپ راه‌دور'],SIP:['☎️','تلفن اینترنتی'],mDNS:['🔎','کشف محلی'],LLMNR:['🔎','نام‌یابی محلی'],NBNS:['🔎','NetBIOS'],SSDP:['📺','کشف دستگاه'],Syslog:['📜','لاگ شبکه'],QUIC:['⚡','QUIC/HTTP3'],BitTorrent:['🧲','تورنت'],TCP:['🔌','TCP ناشناخته'],UDP:['🔌','UDP ناشناخته'],ICMPv6:['📶','ICMPv6'],CARVED:['🧬','استخراج‌شده']};
const pm=n=>PM[n]||['🔌',''];
const SEVC=D.sev_color,SEVF=D.sev_fa;
const sevb=s=>el('span',{class:'sev',style:'background:'+SEVC[s]},T(SEVF[s]||s));
// ---------- state
const DEF={theme:D.meta.theme,material:D.meta.material,grid:1,scan:0,glow:1,rain:0,anim:1,density:'comfortable',fs:14,dir:LANGX==='fa'?'rtl':'ltr',simple:0};
let S=Object.assign({},DEF);try{Object.assign(S,JSON.parse(localStorage.getItem('pcapx')||'{}'))}catch(e){}
if(!D.themes[S.theme])S.theme=DEF.theme;
function applyS(){const h=document.documentElement;h.dataset.lang=LANGX;h.lang=LANGX;h.dataset.theme=S.theme;h.dataset.material=S.material;h.dataset.grid=S.grid;h.dataset.scan=S.scan;h.dataset.glow=S.glow;h.dataset.rain=S.rain;h.dataset.anim=S.anim;h.dataset.density=S.density;h.style.setProperty('--fs',S.fs+'px');h.dir=(S.dirFor===LANGX&&S.dir)?S.dir:(LANGX==='fa'?'rtl':'ltr');document.body.classList.toggle('simple',!!S.simple);
 try{localStorage.setItem('pcapx',JSON.stringify(S))}catch(e){}rain()}
function toast(t){const e=$('#toast');e.textContent=t;e.style.display='block';clearTimeout(toast.t);toast.t=setTimeout(()=>e.style.display='none',1600)}
function copy(t){(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>toast('✔ کپی شد'),()=>{const a=el('textarea',{},t);document.body.append(a);a.select();try{document.execCommand('copy');toast('✔ کپی شد')}catch(e){}a.remove()})}
function dl(name,text,mime){const a=el('a',{href:URL.createObjectURL(new Blob([text],{type:mime||'text/plain'})),download:name});document.body.append(a);a.click();a.remove()}
// ---------- indices
const key2=(a,b)=>a<b?a+'|'+b:b+'|'+a;
const evByPair={};let allEv=[];
for(const p in D.events)for(const e of D.events[p]){e._p=p;allEv.push(e);(evByPair[key2(e.a,e.b)]=evByPair[key2(e.a,e.b)]||[]).push(e)}
const filesByPair={};for(const f of D.files){if(f.src&&f.dst)(filesByPair[key2(f.src,f.dst)]=filesByPair[key2(f.src,f.dst)]||[]).push(f)}
const fileById={};D.files.forEach(f=>fileById[f.id]=f);
// ---------- generic sortable table
function dtable(o){const cols=o.cols;let rows=o.rows.slice(),sk=o.sort||null,sd=o.dir||-1,lim=o.page||150,q='';
 const box=el('div'),tools=el('div',{class:'row',style:'margin-bottom:8px'}),tw=el('div',{class:'tw'}),info=el('span',{class:'muted'});
 const search=el('input',{type:'search',placeholder:'🔍 جستجو…',oninput:e=>{q=e.target.value.toLowerCase();draw()}});
 if(o.search!==false)tools.append(search);(o.tools||[]).forEach(t=>tools.append(t));tools.append(info);
 function val(c,r){return c.v?c.v(r):''}
 function draw(){let rs=rows;if(q)rs=rs.filter(r=>cols.some(c=>String(val(c,r)).toLowerCase().includes(q)));
  if(sk!=null){const c=cols[sk];rs=rs.slice().sort((a,b)=>{const x=val(c,a),y=val(c,b);return (typeof x==='number'&&typeof y==='number'?x-y:String(x).localeCompare(String(y)))*sd})}
  const t=el('table'),th=el('tr');cols.forEach((c,i)=>th.append(el('th',{onclick:()=>{sd=sk===i?-sd:-1;sk=i;draw()}},c.h+(sk===i?(sd>0?' ▲':' ▼'):''))));t.append(el('thead',{},th));
  const tb=el('tbody');rs.slice(0,lim).forEach(r=>{const tr=el('tr',{class:(o.click?'click ':'')+(r.x?'x'+r.x:''),onclick:o.click?()=>o.click(r):null});cols.forEach(c=>tr.append(el('td',{class:c.cls||''},c.r?c.r(r):val(c,r))));tb.append(tr)});t.append(tb);
  tw.replaceChildren(rs.length?t:el('div',{class:'empty'},'موردی یافت نشد'));
  info.textContent=num(Math.min(lim,rs.length))+' از '+num(rs.length)+(rs.length>lim?'  ':'');if(rs.length>lim){info.append(' ',el('button',{class:'btn',onclick:()=>{lim+=300;draw()}},'نمایش بیشتر'))}}
 box.append(tools,tw);draw();return box}
// ---------- modal
function modal(title,...kids){const ov=$('#ov'),b=$('#ovb');b.replaceChildren(el('button',{class:'btn x',onclick:()=>ov.classList.remove('on')},'✕'),el('h2',{},title),...kids);ov.classList.add('on');ov.scrollTop=0}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){$('#ov').classList.remove('on');$('#drawer').classList.remove('on')}});
function kv(obj){const dl_=el('dl',{class:'kvg'});for(const k in obj){if(obj[k]==null||obj[k]==='')continue;dl_.append(el('dt',{},k),el('dd',{class:'ltr'},obj[k]))}return dl_}
const route=(e)=>el('a',{href:'#',class:'ltr',onclick:ev=>{ev.preventDefault();ev.stopPropagation();showPair(e.a,e.b)}},e.a+(e.ap?':'+e.ap:'')+' → '+e.b+(e.bp?':'+e.bp:''));
// ---------- views registry
const VIEWS=[['overview','🛰️','نمای کلی'],['protocols','🧩','پروتکل‌ها'],['routes','🛣️','مسیرها'],['graph','🕸️','گراف شبکه'],['files','🗜️','فایل‌ها (ZIP)'],['findings','🚨','هشدارها'],['intel','🧠','شناخت تهدید'],['stats','📈','آمار']];
const nav=$('#nav'),main=$('#main'),views={};
function go(v,arg){S.view=v;for(const k in views){views[k].el.classList.toggle('on',k===v)}nav.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.v===v));
 const vv=views[v];if(!vv.built){vv.built=true;vv.el.append(...vv.build())}if(vv.focus&&arg!==undefined)vv.focus(arg);history.replaceState(null,'','#'+v+(arg?'/'+encodeURIComponent(arg):''));window.scrollTo(0,0)}
function reg(id,badge,build,focus){const e=el('section',{class:'view'});views[id]={el:e,build,focus};main.append(e)}
// ============ OVERVIEW
reg('overview',0,()=>{const R=D.risk,out=[];
 const col=R.score>=75?'var(--bad)':R.score>=50?'var(--orange)':R.score>=25?'var(--warn)':'var(--ok)';const c=2*Math.PI*52;
 const gauge=el('div',{style:'text-align:center'});gauge.innerHTML='<svg width="140" height="140" viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="none" stroke="currentColor" stroke-opacity=".15" stroke-width="9"/><circle cx="60" cy="60" r="52" fill="none" stroke="'+col+'" stroke-width="9" stroke-linecap="round" stroke-dasharray="'+c.toFixed(1)+'" stroke-dashoffset="'+(c*(1-R.score/100)).toFixed(1)+'" transform="rotate(-90 60 60)" style="filter:drop-shadow(0 0 6px '+col+')"/><text x="60" y="68" text-anchor="middle" fill="currentColor" font-size="28" font-weight="800">'+R.score+'</text></svg>';
 out.push(el('div',{class:'card verdict'},el('div',{class:'big'},D.verdict[0]),el('div',{style:'flex:1;min-width:240px'},el('h2',{},D.verdict[1]),el('p',{class:'muted'},D.verdict[2]),el('div',{class:'row'},el('span',{class:'chip acc'},'ریسک: '+T(R.level_fa)),el('span',{class:'chip'},'اطمینان: '+R.confidence+'%'),el('span',{class:'chip'},D.meta.start+' → '+D.meta.end),el('span',{class:'chip'},dur(D.meta.duration)))),gauge));
 const st=D.stats;out.push(el('div',{class:'grid g4'},...[['بسته‌ها',num(st.packets)],['حجم',hb(st.bytes)],['میزبان یکتا',num(st.unique_ips)],['جریان‌ها',num(D.flows_total)],['پروتکل‌ها',num(D.protocols.length)],['فایل استخراج‌شده',num(D.files.length)],['هشدارها',num(D.findings.length)],['رویداد پروتکل',num(Object.values(D.events_total).reduce((a,b)=>a+b,0))]].map(([l,v])=>el('div',{class:'card stat'},el('div',{class:'v acc glow'},v),el('div',{class:'l'},l)))));
 // timeline
 const bins=D.timeline,mx=Math.max(...bins,1),W=1000,H=120;const pts=bins.map((v,i)=>[i*W/Math.max(bins.length-1,1),H-8-(v/mx)*(H-20)]);const ln=pts.map(p=>p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ');
 const tl=el('div',{class:'card'},el('h3',{},'نرخ ترافیک در زمان'));const sv=el('div');sv.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="100%" height="120" preserveAspectRatio="none"><defs><linearGradient id="tg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" style="stop-color:var(--acc)" stop-opacity=".5"/><stop offset="1" style="stop-color:var(--acc)" stop-opacity="0"/></linearGradient></defs><polygon points="0,'+H+' '+ln+' '+W+','+H+'" fill="url(#tg)"/><polyline points="'+ln+'" fill="none" stroke="var(--acc)" stroke-width="2.4" style="filter:drop-shadow(0 0 4px var(--acc))"/></svg>';tl.append(sv);out.push(tl);
 // protocols quick bars
 const pr=D.protocols.slice(0,12),pmx=Math.max(...pr.map(p=>p.bytes+p.events*100),1);
 out.push(el('div',{class:'grid g2'},el('div',{class:'card'},el('h3',{},'پروتکل‌ها — کلیک کنید تا جزئیات را ببینید'),...pr.map(p=>el('div',{class:'row',style:'cursor:pointer;margin:6px 0',onclick:()=>go('protocols',p.name)},el('span',{style:'width:110px;font-weight:800'},pm(p.name)[0]+' '+p.name),el('div',{class:'barbg',style:'flex:1'},el('div',{class:'bar',style:'width:'+Math.max(2,(p.bytes+p.events*100)/pmx*100)+'%'})),el('span',{class:'mono dim',style:'width:130px;text-align:end'},hb(p.bytes)+' · '+num(p.events)+' ev')))),
  el('div',{class:'card'},el('h3',{},'داستان فایل‌ها (چه کسی از کجا چه دانلود کرد)'),D.http_story.length?el('div',{class:'story'},...D.http_story.slice(0,8).map(s=>el('div',{class:'it'},s.text))):el('div',{class:'empty'},'دانلود فایلی از HTTP پیدا نشد'))));
 out.push(el('div',{class:'card'},el('h3',{},'خلاصه مدیریتی'),el('p',{},D.corr.executive_summary)));
 const top=D.findings.slice(0,5);out.push(el('div',{class:'card'},el('h3',{},'مهم‌ترین هشدارها'),top.length?top.map(f=>el('div',{class:'row',style:'margin:6px 0;cursor:pointer',onclick:()=>go('findings',f.id)},sevb(f.severity),el('b',{},FL(f,'title')),el('span',{class:'chip'},'x'+num(f.count)))):el('div',{class:'empty'},'✅ مورد مشکوکی نبود')));
 return out});
// ============ PROTOCOLS
let curProto=null,curTab={};
reg('protocols',0,()=>{const box=el('div',{class:'split'});const list=el('div',{class:'plist panel'}),det=el('div',{class:'panel',id:'pdet'});box.append(list,det);views.protocols.list=list;views.protocols.det=det;
 D.protocols.forEach(p=>{const m=pm(p.name);list.append(el('button',{class:'pcard','data-p':p.name,onclick:()=>openProto(p.name)},el('div',{class:'top'},el('span',{class:'ic'},m[0]),p.name,p.flagged?el('span',{class:'tag warn'},'⚑ '+p.flagged):null),el('div',{class:'dim',style:'font-size:11.5px'},m[1]),el('div',{class:'meta'},el('span',{},num(p.flows)+' جریان'),el('span',{},hb(p.bytes)),el('span',{},num(p.events)+' رویداد'))))});
 if(D.protocols.length)openProto(curProto||D.protocols[0].name);else det.append(el('div',{class:'empty'},'پروتکلی یافت نشد'));return [box]},p=>openProto(p));
function openProto(name){curProto=name;const v=views.protocols;if(!v.list)return;v.list.querySelectorAll('.pcard').forEach(b=>b.classList.toggle('on',b.dataset.p===name));
 const P=D.protocols.find(x=>x.name===name);if(!P)return;const m=pm(name),evs=D.events[name]||[],flows=D.flows.filter(f=>f.p===name),fnd=D.findings_by_proto[name]||[];
 const head=el('div',{},el('div',{class:'row'},el('h2',{},m[0]+' '+name),el('span',{class:'muted'},m[1])),el('div',{class:'row',style:'margin:6px 0'},el('span',{class:'chip acc'},num(P.flows)+' جریان'),el('span',{class:'chip'},num(P.packets)+' بسته'),el('span',{class:'chip'},hb(P.bytes)),el('span',{class:'chip'},'↑ '+hb(P.up)+'  ↓ '+hb(P.down)),el('span',{class:'chip'},num(P.hosts)+' میزبان'),el('span',{class:'chip'},tsf(P.t0)+' → '+tsf(P.t1)),P.flagged?el('span',{class:'chip warn'},'⚑ '+P.flagged+' مورد قابل‌توجه'):null,(D.events_total[name]||0)>evs.length?el('span',{class:'chip'},'نمایش '+num(evs.length)+' از '+num(D.events_total[name])):null));
 const tabs=[];const body=el('div',{style:'margin-top:10px'});
 const add=(id,label,fn)=>tabs.push({id,label,fn});
 if(name==='HTTP'){add('tx','تراکنش‌ها',()=>httpTx(evs));add('dl','فایل‌های دانلود',()=>fileTable(D.files.filter(f=>f.proto==='HTTP'&&f.direction==='download')));add('up','آپلودها',()=>fileTable(D.files.filter(f=>f.proto==='HTTP'&&f.direction==='upload')));add('hosts','میزبان‌ها',()=>httpAgg(evs,'host'));add('ua','User-Agent',()=>httpAgg(evs,'ua'));add('st','وضعیت/نوع',()=>httpStatus(evs))}
 else if(name==='DNS'){add('dom','دامنه‌ها',()=>dnsAgg(evs));add('ev','پرسش/پاسخ‌ها',()=>evTable(evs))}
 else if(name==='TLS'){add('sni','SNI و JA3',()=>tlsAgg(evs));add('ev','Handshakeها',()=>evTable(evs))}
 else if(['FTP','SMTP','POP3','TFTP'].includes(name)){add('ev','رویدادها',()=>evTable(evs));add('fl','فایل‌ها',()=>fileTable(D.files.filter(f=>f.proto===name)))}
 else add('ev','رویدادها',()=>evTable(evs));
 add('flows','جریان‌ها',()=>flowTable(flows));if(fnd.length)add('fnd','هشدارهای مرتبط ('+fnd.length+')',()=>findLite(fnd));
 const bar=el('div',{class:'tabs'});const sel=curTab[name]&&tabs.find(t=>t.id===curTab[name])?curTab[name]:tabs[0].id;
 function show(id){curTab[name]=id;bar.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.t===id));body.replaceChildren(tabs.find(t=>t.id===id).fn())}
 tabs.forEach(t=>bar.append(el('button',{'data-t':t.id,onclick:()=>show(t.id)},t.label)));
 const story=name==='HTTP'&&D.http_story.length?el('div',{class:'story',style:'margin:8px 0'},...D.http_story.slice(0,4).map(s=>el('div',{class:'it'},s.text))):null;
 v.det.replaceChildren(head,story,bar,body);show(sel)}
function evTable(evs){return dtable({rows:evs,sort:0,dir:1,click:e=>evModal(e),cols:[{h:'زمان',v:e=>e.t||0,r:e=>e.ts.slice(11),cls:'mono'},{h:'مسیر',v:e=>e.a+e.b,r:e=>route(e),cls:'nw'},{h:'نوع',v:e=>e.k,r:e=>el('span',{class:'tag acc'},e.k)},{h:'خلاصه',v:e=>e.s,cls:'ltr'},{h:'⚑',v:e=>e.x,r:e=>e.x?el('span',{class:'tag '+(e.x>1?'bad':'warn')},e.x>1?'خطر':'توجه'):''}]})}
function evModal(e){const d=e.d||{},o={};for(const k in d){if(k==='req_head'||k==='resp_head')continue;const v=d[k];o[k]=Array.isArray(v)?v.join(' | '):(typeof v==='object'&&v?JSON.stringify(v):v)}
 modal(pm(e._p||e.p)[0]+' '+e.p+' · '+e.k,kv(Object.assign({'زمان':e.ts,'بسته':e.n,'مسیر':e.a+':'+e.ap+' → '+e.b+':'+e.bp,'خلاصه':e.s},o)),d.req_head?el('div',{},el('h3',{},'درخواست (هدرها)'),el('pre',{},d.req_head)):null,d.resp_head?el('div',{},el('h3',{},'پاسخ (هدرها)'),el('pre',{},d.resp_head)):null,e.f?el('div',{},el('h3',{},'فایل مرتبط'),fileTable([fileById[e.f]].filter(Boolean))):null)}
function httpTx(evs){const sc=s=>'st'+String(s||0)[0];return dtable({rows:evs,sort:0,dir:1,click:e=>evModal(e),cols:[
 {h:'زمان',v:e=>e.t||0,r:e=>e.ts.slice(11),cls:'mono'},{h:'کلاینت → سرور',v:e=>e.a+e.b,r:e=>route(e),cls:'nw'},{h:'متد',v:e=>e.d.method,cls:'mono'},
 {h:'URL',v:e=>e.d.host+e.d.uri,r:e=>el('span',{},e.d.host,el('span',{class:'dim'},e.d.uri.slice(0,140))),cls:'ltr'},
 {h:'وضعیت',v:e=>e.d.status||0,r:e=>el('b',{class:sc(e.d.status)},e.d.status||'—')},{h:'نوع',v:e=>e.d.ctype,cls:'ltr'},{h:'حجم',v:e=>e.d.size,r:e=>hb(e.d.size)},
 {h:'فایل',v:e=>e.d.filename||'',r:e=>e.f&&fileById[e.f]?el('a',{href:'#',onclick:ev=>{ev.preventDefault();ev.stopPropagation();fileModal(fileById[e.f])}},'📄 '+fileById[e.f].name):(e.d.uploads&&e.d.uploads.length?e.d.uploads.map(u=>el('span',{class:'tag warn'},'⬆ '+u.name)):'')},
 {h:'پرچم',v:e=>(e.d.flags||[]).join(),r:e=>(e.d.flags||[]).map(f=>el('span',{class:'tag '+(['risky-file','ext-mismatch','ip-host','big-post'].includes(f)?'bad':'')},f))}]})}
function httpAgg(evs,k){const m={};evs.forEach(e=>{const v=e.d[k]||'—',r=m[v]=m[v]||{k:v,n:0,b:0,f:0,c:new Set()};r.n++;r.b+=e.d.size||0;if(e.f)r.f++;r.c.add(e.a)});
 return dtable({rows:Object.values(m),sort:1,cols:[{h:k==='host'?'میزبان':'User-Agent',v:r=>r.k,cls:'ltr'},{h:'درخواست',v:r=>r.n},{h:'حجم پاسخ',v:r=>r.b,r:r=>hb(r.b)},{h:'فایل',v:r=>r.f},{h:'کلاینت‌ها',v:r=>[...r.c].join(' '),cls:'ltr'}]})}
function httpStatus(evs){const s={},t={};evs.forEach(e=>{s[e.d.status||0]=(s[e.d.status||0]||0)+1;const c=e.d.ctype||'—';t[c]=(t[c]||0)+1});
 const bars=(o,fmt)=>{const a=Object.entries(o).sort((x,y)=>y[1]-x[1]).slice(0,20),m=a[0]?a[0][1]:1;return a.map(([k,v])=>el('div',{class:'row',style:'margin:4px 0'},el('span',{class:'mono',style:'width:200px;overflow:hidden'},k),el('div',{class:'barbg',style:'flex:1'},el('div',{class:'bar',style:'width:'+(v/m*100)+'%'})),el('b',{},v)))};
 return el('div',{class:'grid g2'},el('div',{class:'card'},el('h3',{},'کدهای وضعیت'),...bars(s)),el('div',{class:'card'},el('h3',{},'نوع محتوا'),...bars(t)))}
function dnsAgg(evs){const m={};evs.forEach(e=>{const n=e.d.name||e.s,r=m[n]=m[n]||{n,c:0,a:new Set(),rc:new Set(),t:new Set(),cl:new Set(),x:0};r.c++;(e.d.answers||[]).forEach(a=>r.a.add(a));if(e.d.rcode)r.rc.add(e.d.rcode);if(e.d.qtype)r.t.add(e.d.qtype);r.cl.add(e.a);r.x=Math.max(r.x,e.x)});
 return dtable({rows:Object.values(m),sort:1,click:r=>modal('DNS · '+r.n,kv({'دامنه':r.n,'تعداد پرسش':r.c,'نوع':[...r.t].join(', '),'پاسخ‌ها':[...r.a].join('\n'),'rcode':[...r.rc].join(', '),'کلاینت‌ها':[...r.cl].join(', ')})),cols:[{h:'دامنه',v:r=>r.n,cls:'ltr'},{h:'تعداد',v:r=>r.c},{h:'نوع',v:r=>[...r.t].join(',')},{h:'پاسخ',v:r=>[...r.a].join(' , '),cls:'ltr'},{h:'rcode',v:r=>[...r.rc].join(','),r:r=>[...r.rc].map(x=>el('span',{class:'tag '+(x==='NOERROR'?'ok':'warn')},x))},{h:'کلاینت',v:r=>[...r.cl].join(' '),cls:'ltr'}]})}
function tlsAgg(evs){const m={};evs.forEach(e=>{const n=(e.d.sni||e.b)+'|'+(e.d.ja3||''),r=m[n]=m[n]||{sni:e.d.sni||'(بدون SNI)',ja3:e.d.ja3||'',v:e.d.version||'',alpn:e.d.alpn||'',c:0,cl:new Set(),srv:e.b,kn:e.d.known_client,x:0};r.c++;r.cl.add(e.a);r.x=Math.max(r.x,e.x)});
 return dtable({rows:Object.values(m),sort:3,cols:[{h:'SNI',v:r=>r.sni,cls:'ltr'},{h:'سرور',v:r=>r.srv,cls:'ltr'},{h:'نسخه',v:r=>r.v},{h:'تعداد',v:r=>r.c},{h:'ALPN',v:r=>r.alpn,cls:'ltr'},{h:'JA3',v:r=>r.ja3,cls:'ltr'},{h:'کلاینت شناخته‌شده',v:r=>r.kn?r.kn[0]:'',r:r=>r.kn?el('span',{class:'tag '+(r.kn[1]?'bad':'ok')},r.kn[0]):''}]})}
function flowTable(fl){return dtable({rows:fl,sort:6,cols:[{h:'مبدأ',v:f=>f.a+':'+f.ap,cls:'ltr'},{h:'مقصد',v:f=>f.b+':'+f.bp,cls:'ltr'},{h:'L4',v:f=>f.l4},{h:'پروتکل',v:f=>f.p},{h:'بسته (→/←)',v:f=>f.pk1+f.pk2,r:f=>f.pk1+' / '+f.pk2},{h:'بایت (→/←)',v:f=>f.by1+f.by2,r:f=>hb(f.by1)+' / '+hb(f.by2)},{h:'زمان',v:f=>f.t0,r:f=>tsf(f.t0).slice(11)+' ('+dur(f.t1-f.t0)+')'}],click:f=>showPair(f.a,f.b)})}
function findLite(fnd){return dtable({rows:fnd,search:false,cols:[{h:'شدت',v:f=>f.severity,r:f=>sevb(f.severity)},{h:'عنوان',v:f=>FL(f,'title')},{h:'تعداد',v:f=>f.count},{h:'MITRE',v:f=>f.mitre,cls:'mono'}],click:f=>go('findings',f.id)})}
// ============ ROUTES
function showPair(a,b){const k=key2(a,b),pr=D.pairs.find(p=>key2(p.a,p.b)===k),fl=D.flows.filter(f=>key2(f.a,f.b)===k),ev=evByPair[k]||[],fs=filesByPair[k]||[];
 const tabs=[['ev','رویدادها ('+ev.length+')',()=>evTable(ev.map(e=>e))],['fl','جریان‌ها ('+fl.length+')',()=>flowTable(fl)],['fi','فایل‌ها ('+fs.length+')',()=>fileTable(fs)]];
 const body=el('div'),bar=el('div',{class:'tabs'});tabs.forEach(([id,l,fn],i)=>bar.append(el('button',{'data-t':id,class:i?'':'on',onclick:()=>{bar.querySelectorAll('button').forEach(x=>x.classList.toggle('on',x.dataset.t===id));body.replaceChildren(fn())}},l)));body.append(tabs[0][2]());
 modal('🛣️ '+a+'  ↔  '+b,el('div',{class:'row'},pr?[el('span',{class:'chip acc'},num(pr.flows)+' جریان'),el('span',{class:'chip'},hb(pr.bytes)),el('span',{class:'chip'},tsf(pr.t0)+' → '+tsf(pr.t1))]:null,...(pr?Object.keys(pr.protos).map(p=>el('span',{class:'tag acc',style:'cursor:pointer',onclick:()=>{$('#ov').classList.remove('on');go('protocols',p)}},pm(p)[0]+' '+p)):[])),bar,body)}
reg('routes',0,()=>[el('h2',{},'مسیرهای ارتباطی (میزبان ↔ میزبان)'),el('p',{class:'muted'},'روی هر ردیف کلیک کنید تا بفهمید بین این دو دستگاه دقیقاً چه اتفاقی افتاده (پروتکل‌ها، جریان‌ها، رویدادها و فایل‌ها).'),el('div',{class:'panel'},dtable({rows:D.pairs.map(p=>Object.assign({ev:(evByPair[key2(p.a,p.b)]||[]).length,fi:(filesByPair[key2(p.a,p.b)]||[]).length,x:(evByPair[key2(p.a,p.b)]||[]).some(e=>e.x>1)?2:(evByPair[key2(p.a,p.b)]||[]).some(e=>e.x)?1:0},p)),sort:3,click:p=>showPair(p.a,p.b),cols:[{h:'میزبان A',v:p=>p.a,cls:'ltr'},{h:'میزبان B',v:p=>p.b,cls:'ltr'},{h:'جریان',v:p=>p.flows},{h:'حجم',v:p=>p.bytes,r:p=>hb(p.bytes)},{h:'پروتکل‌ها',v:p=>Object.keys(p.protos).join(),r:p=>Object.keys(p.protos).map(x=>el('span',{class:'tag acc'},x))},{h:'رویداد',v:p=>p.ev},{h:'فایل',v:p=>p.fi},{h:'بازه',v:p=>p.t0,r:p=>dur(p.t1-p.t0)}]}))]);

// ============ GRAPH (self-contained force layout, no libraries)
reg('graph',0,()=>{
 const bad=new Map();D.findings.forEach(f=>{const w={critical:4,high:3,medium:2,low:1}[f.severity]||0;[...(f.actors||[]),...(f.targets||[])].forEach(ip=>bad.set(ip,Math.max(bad.get(ip)||0,w)))});
 const P=D.pairs.slice(0,120),nodes=new Map();
 P.forEach(p=>{[p.a,p.b].forEach(x=>{if(!nodes.has(x))nodes.set(x,{id:x,b:0,deg:0,x:0,y:0,vx:0,vy:0})});nodes.get(p.a).b+=p.bytes;nodes.get(p.b).b+=p.bytes;nodes.get(p.a).deg++;nodes.get(p.b).deg++});
 const N=[...nodes.values()].sort((a,b)=>b.b-a.b).slice(0,70),ix=new Map(N.map((n,i)=>[n.id,i]));
 const E=P.filter(p=>ix.has(p.a)&&ix.has(p.b));
 if(!N.length)return [el('h2',{},'گراف شبکه'),el('div',{class:'empty'},'ارتباطی برای نمایش نیست')];
 const W=1000,H=620;N.forEach((n,i)=>{const a=i*2.399,r=40+Math.sqrt(i)*55;n.x=W/2+Math.cos(a)*r;n.y=H/2+Math.sin(a)*r});
 for(let it=0;it<260;it++){const t=1-it/260;
  for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){const a=N[i],b=N[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+.01;const f=2600/d2*t;const d=Math.sqrt(d2);dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f}
  E.forEach(e=>{const a=N[ix.get(e.a)],b=N[ix.get(e.b)];const dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)+.01,f=(d-90)*.012*t;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f});
  N.forEach(n=>{n.vx+=(W/2-n.x)*.004;n.vy+=(H/2-n.y)*.004;n.x=Math.min(W-30,Math.max(30,n.x+n.vx));n.y=Math.min(H-30,Math.max(30,n.y+n.vy));n.vx*=.6;n.vy*=.6})}
 const col=['#64748b','#38bdf8','#fbbf24','#fb923c','#f43f5e'],mx=Math.max(...E.map(e=>e.bytes),1);
 const x0=Math.min(...N.map(n=>n.x))-50,x1=Math.max(...N.map(n=>n.x))+50,y0=Math.min(...N.map(n=>n.y))-40,y1=Math.max(...N.map(n=>n.y))+30,vw=Math.max(x1-x0,760),vh=Math.max(y1-y0,440);
 let svg='<svg viewBox="'+x0.toFixed(0)+' '+y0.toFixed(0)+' '+vw.toFixed(0)+' '+vh.toFixed(0)+'" width="100%" style="max-height:70vh;background:var(--bg2,transparent);border-radius:12px">';
 E.forEach(e=>{const a=N[ix.get(e.a)],b=N[ix.get(e.b)],hot=Math.max(bad.get(e.a)||0,bad.get(e.b)||0);svg+='<line data-a="'+e.a+'" data-b="'+e.b+'" x1="'+a.x.toFixed(1)+'" y1="'+a.y.toFixed(1)+'" x2="'+b.x.toFixed(1)+'" y2="'+b.y.toFixed(1)+'" stroke="'+col[hot]+'" stroke-opacity="'+(hot?.7:.35)+'" stroke-width="'+(1+4*Math.sqrt(e.bytes/mx)).toFixed(1)+'" style="cursor:pointer"><title>'+e.a+' ↔ '+e.b+' · '+hb(e.bytes)+'</title></line>'});
 const nm=Math.max(...N.map(n=>n.b),1);
 N.forEach(n=>{const r=5+11*Math.sqrt(n.b/nm),k=bad.get(n.id)||0;svg+='<g class="gn" data-id="'+n.id+'" style="cursor:pointer"><circle cx="'+n.x.toFixed(1)+'" cy="'+n.y.toFixed(1)+'" r="'+r.toFixed(1)+'" fill="'+col[k]+'" fill-opacity=".85" stroke="#fff" stroke-opacity=".5"/><text x="'+n.x.toFixed(1)+'" y="'+(n.y-r-3).toFixed(1)+'" text-anchor="middle" font-size="10" fill="currentColor" style="direction:ltr">'+n.id+'</text><title>'+n.id+' · '+hb(n.b)+'</title></g>'});
 svg+='</svg>';
 const box=el('div',{class:'panel'});box.innerHTML=svg;
 box.querySelectorAll('line').forEach(l=>l.onclick=()=>showPair(l.dataset.a,l.dataset.b));
 box.querySelectorAll('.gn').forEach(g=>g.onclick=()=>{const p=E.find(e=>e.a===g.dataset.id||e.b===g.dataset.id);if(p)showPair(p.a,p.b)});
 const lg=el('div',{class:'row',style:'gap:14px;margin-top:8px;flex-wrap:wrap'},...[['عادی',0],['کم',1],['متوسط',2],['زیاد',3],['بحرانی',4]].map(([l,i])=>el('span',{class:'muted'},el('span',{style:'display:inline-block;width:10px;height:10px;border-radius:50%;background:'+col[i]+';margin-inline-end:5px'}),l)));
 return [el('h2',{},'گراف شبکه'),el('p',{class:'muted'},'اندازه‌ی گره = حجم ترافیک · ضخامت یال = حجم بین دو میزبان · رنگ = بالاترین شدت هشدار مرتبط. روی گره یا یال کلیک کنید.'),box,lg]});
// ============ FILES (ZIP explorer)
function fileModal(f){const pv=f.preview||{};let pe=null;
 if(pv.k==='image'&&/^data:image\/(png|jpeg|gif|webp|bmp|x-icon);base64,/.test(pv.v))pe=el('img',{src:pv.v,style:'max-width:100%;max-height:300px;image-rendering:pixelated;border:1px solid var(--line);border-radius:8px;background:#fff'});
 else if(pv.v)pe=el('pre',{},pv.v);
 const hs=['sha256','md5','sha1','crc32'].map(h=>el('div',{class:'row'},el('b',{style:'width:60px'},h),el('code',{class:'ltr',style:'flex:1;overflow-wrap:anywhere'},f[h]),el('button',{class:'btn',onclick:()=>copy(f[h])},'کپی')));
 modal('📄 '+f.name,el('div',{class:'row',style:'margin-bottom:8px'},el('span',{class:'tag acc'},f.type),el('span',{class:'tag'},f.category_fa),f.risky?el('span',{class:'tag bad'},'⚠ اجرایی/پرخطر'):null,f.mismatch?el('span',{class:'tag bad'},'پسوند با محتوا نمی‌خواند ('+f.ext_real+')'):null,(f.flags||[]).filter(x=>x!=='ext-mismatch').map(x=>el('span',{class:'tag warn'},x))),
  kv({'نام اصلی':f.name,'منبع نام':f.name_source,'مسیر در ZIP':f.zip_path,'پروتکل':f.proto+(f.direction?' ('+f.direction+')':''),'میزبان':f.host,'URL':f.url,'از':f.src,'به':f.dst,'زمان':f.ts_str,'جریان':f.flow,'بسته':f.n,'حجم':num(f.size)+' B ('+hb(f.size)+')'+(f.packed!=null?' · فشرده '+hb(f.packed):''),'آنتروپی':f.entropy,'Content-Type':f.mime,'توضیح':f.note}),
  el('h3',{style:'margin-top:12px'},'هش‌ها'),...hs,el('h3',{style:'margin-top:12px'},'پیش‌نمایش امن ('+(pv.k||'-')+')'),pe,f.event!=null?el('button',{class:'btn',style:'margin-top:8px',onclick:()=>{$('#ov').classList.remove('on');go('protocols',f.proto);curTab[f.proto]='tx'}},'↗ رفتن به تراکنش '+f.proto):null)}
function fileTable(fs){return dtable({rows:fs,sort:0,dir:1,click:fileModal,cols:[{h:'#',v:f=>f.id},{h:'نام فایل',v:f=>f.name,r:f=>el('b',{},f.name)},{h:'نوع واقعی',v:f=>f.type,r:f=>el('span',{},f.type,f.mismatch?el('span',{class:'tag bad'},'≠پسوند'):null)},{h:'حجم',v:f=>f.size,r:f=>hb(f.size)},{h:'منبع',v:f=>(f.host||'')+(f.url||''),r:f=>el('span',{class:'ltr dim'},f.host||f.src||'')},{h:'SHA-256',v:f=>f.sha256,r:f=>f.sha256.slice(0,16)+'…',cls:'mono'},{h:'⚑',v:f=>f.risky?2:0,r:f=>f.risky?el('span',{class:'tag bad'},'خطر'):''}]})}
reg('files',0,()=>{const FS=D.files_summary,out=[];
 out.push(el('h2',{},'مرورگر ZIP فایل‌های استخراج‌شده'));
 if(!D.files.length){out.push(el('div',{class:'card empty'},'هیچ فایلی از ترافیک استخراج نشد (یا استخراج غیرفعال بود: --no-extract).'));return out}
 const cmd=FS.mode==='aes'?'7z x -p'+FS.password+' "'+FS.zip+'"':'unzip "'+FS.zip+'"   # فایل‌های خطرناک: *.sample (python pcap_analyzer.py --restore)';
 out.push(el('div',{class:'card zipbar'},el('div',{class:'zipico'},'🗜️'),el('div',{style:'flex:1;min-width:260px'},el('b',{class:'ltr',style:'font-size:16px'},FS.zip),el('div',{class:'muted'},num(FS.count)+' فایل · '+hb(FS.bytes)+' · '+(FS.mode==='aes'?'رمزدار AES-256 — رمز: ':'بدون رمز (ظرف خنثی برای فایل‌های خطرناک)')+(FS.password||'')),FS.risky?el('div',{class:'tag bad'},'⚠ '+FS.risky+' فایل اجرایی/پرخطر — فقط داخل VM باز کنید'):null),
  el('a',{class:'btn pri',href:/^[\w .()\-]+\.zip$/.test(FS.zip)?FS.zip:'#',download:FS.zip},'⬇ دانلود ZIP'),el('button',{class:'btn',onclick:()=>copy(cmd)},'کپی دستور باز کردن'),el('button',{class:'btn',onclick:()=>dl('files_list.csv',csv(),'text/csv')},'خروجی CSV فهرست')));
 function csv(){const c=['id','name','zip_path','proto','host','url','direction','size','type','sha256','md5','crc32'];return [c.join(',')].concat(D.files.map(f=>c.map(k=>'"'+String(f[k]==null?'':f[k]).replace(/"/g,'""')+'"').join(','))).join('\n')}
 const cats=Object.entries(FS.by_category||{}).sort((a,b)=>b[1].bytes-a[1].bytes);let cf='',q='',riskOnly=false,mode='tree';
 const chips=el('div',{class:'row'}),cont=el('div',{class:'card'});
 const catName=c=>(D.files.find(f=>FL(f,'category')===c)||{}).category_fa||c;
 function chipsDraw(){chips.replaceChildren(el('button',{class:'btn'+(cf===''&&!riskOnly?' on':''),onclick:()=>{cf='';riskOnly=false;draw()}},'همه '+D.files.length),...cats.map(([c,v])=>el('button',{class:'btn'+(cf===c?' on':''),onclick:()=>{cf=c;draw()}},catName(c)+' '+v.count)),el('button',{class:'btn'+(riskOnly?' on':''),onclick:()=>{riskOnly=!riskOnly;draw()}},'⚠ فقط پرخطر'),el('button',{class:'btn'+(mode==='tree'?' on':''),onclick:()=>{mode='tree';draw()}},'🌲 درخت'),el('button',{class:'btn'+(mode==='table'?' on':''),onclick:()=>{mode='table';draw()}},'▦ جدول'))}
 function draw(){chipsDraw();let fs=D.files.filter(f=>(!cf||FL(f,'category')===cf)&&(!riskOnly||f.risky)&&(!q||(f.name+f.host+f.sha256+f.type+(f.url||'')).toLowerCase().includes(q)));
  if(mode==='table'){cont.replaceChildren(fileTable(fs));return}
  const root={d:{},f:[]};fs.forEach(f=>{const parts=(f.zip_path||('?/'+f.name)).split('/');let n=root;parts.slice(0,-1).forEach(p=>n=n.d[p]=n.d[p]||{d:{},f:[]});n.f.push(f)});
  const hd=el('div',{class:'frow fhead'},el('span',{},'نام (مسیر داخل ZIP)'),el('span',{},'حجم'),el('span',{},'فشرده'),el('span',{},'نوع'),el('span',{},'CRC32 / SHA-256'));
  function node(n,open){const fr=document.createDocumentFragment();Object.keys(n.d).sort().forEach(k=>{const cnt=c=>c.f.length+Object.values(c.d).reduce((a,x)=>a+cnt(x),0);const dt=el('details',{open:(open||fs.length<=80)?'':null},el('summary',{},'📂 '+k+'  ',el('span',{class:'dim'},'('+cnt(n.d[k])+')')));dt.append(node(n.d[k],false));fr.append(dt)});
   n.f.sort((a,b)=>a.name.localeCompare(b.name)).forEach(f=>fr.append(el('div',{class:'frow',onclick:()=>fileModal(f)},el('span',{class:'nm'},(f.risky?'⚠️ ':'📄 ')+f.name,f.mismatch?el('span',{class:'tag bad'},'≠پسوند'):null),el('span',{class:'mono'},hb(f.size)),el('span',{class:'mono dim'},f.packed!=null?hb(f.packed):'—'),el('span',{class:'dim'},f.type),el('span',{class:'mono dim'},f.crc32+' · '+f.sha256.slice(0,12)+'…'))));return fr}
  const tr=el('div',{class:'tree'},hd);tr.append(node(root,true));cont.replaceChildren(tr)}
 out.push(el('div',{class:'row'},el('input',{type:'search',placeholder:'🔍 نام فایل، میزبان، هش، نوع…',style:'flex:1',oninput:e=>{q=e.target.value.toLowerCase();draw()}})),chips,cont);draw();return out});
// ============ FINDINGS
reg('findings',0,()=>{let sv='all',q='';const list=el('div');
 function draw(){list.replaceChildren(...D.findings.filter(f=>(sv==='all'||f.severity===sv)&&(!q||JSON.stringify(f).toLowerCase().includes(q))).map(f=>{const d=el('details',{class:'f',id:'f-'+f.id,open:['critical','high'].includes(f.severity)?'':null},el('summary',{},sevb(f.severity),el('b',{style:'flex:1;min-width:220px'},FL(f,'title')),el('span',{class:'tag acc'},'ATT&CK '+f.mitre),el('span',{class:'tag ok'},f.d3fend),el('span',{class:'chip'},'x'+num(f.count))),
   el('div',{class:'bd'},el('div',{class:'plain'},el('div',{class:'w'},el('b',{},'🧐 چه اتفاقی افتاده؟ '),(LANGX==='en'?(f.plain_en||f.plain):f.plain)[0]),(LANGX==='en'?(f.plain_en||f.plain):f.plain)[1]?el('div',{class:'y'},el('b',{},'⚠️ چرا مهم است؟ '),(LANGX==='en'?(f.plain_en||f.plain):f.plain)[1]):null,el('div',{class:'t'},el('b',{},'✅ الان چه کنم؟ '),(LANGX==='en'?(f.plain_en||f.plain):f.plain)[2])),
    el('div',{class:'tech'},el('p',{class:'muted'},FL(f,'description')),kv({'دسته':FL(f,'category'),'Kill Chain':f.kill_chain,'MITRE CAR':f.car,'اولین مشاهده':f.first_ts,'مبدأها':f.actors.slice(0,12).join(', '),'مقصدها':f.targets.slice(0,12).join(', ')}),...f.evidence.map(e=>el('pre',{},e)),el('div',{class:'card',style:'border-color:var(--ok)'},'🛡️ ',FL(f,'recommendation')))));return d}));if(!list.children.length)list.append(el('div',{class:'empty'},'✅ موردی نیست'))}
 const bar=el('div',{class:'row'},el('input',{type:'search',placeholder:'🔍 عنوان، IP، MITRE، شواهد…',style:'flex:1',oninput:e=>{q=e.target.value.toLowerCase();draw()}}),...['all','critical','high','medium','low','info'].map(s=>el('button',{class:'btn'+(s==='all'?' on':''),onclick:ev=>{sv=s;bar.querySelectorAll('.btn').forEach(b=>b.classList.remove('on'));ev.target.classList.add('on');draw()}},s==='all'?'همه':SEVF[s])));
 draw();return [el('h2',{},'هشدارها و یافته‌های امنیتی'),bar,list]},id=>{const e=$('#f-'+id);if(e){e.open=true;setTimeout(()=>e.scrollIntoView({behavior:'smooth',block:'center'}),50)}});
// ============ INTEL
reg('intel',0,()=>{const C=D.corr,out=[];
 out.push(el('h2',{},'زنجیره کشتار سایبری'),el('div',{class:'kc'},...C.kill_chain.map(k=>el('div',{class:'kcn'+(k.active?' on':'')},el('b',{},k.stage_fa),el('div',{class:k.active?'':'dim',style:'font-size:12px'},k.active?'🚨 '+num(k.count)+' رخداد':'⚪ بدون رخداد'),el('div',{class:'dim',style:'font-size:11px'},k.findings.slice(0,3).join(' · '))))));
 const dm={adversary:'👤 مهاجم',capability:'⚔️ قابلیت/ابزار',infrastructure:'🌐 زیرساخت',victim:'🎯 قربانی'};
 out.push(el('h2',{},'مدل الماس'),el('div',{class:'grid g4'},...Object.entries(dm).map(([k,l])=>el('div',{class:'card'},el('h3',{},l),...(C.diamond_model[k]||[]).slice(0,30).map(x=>el('span',{class:'pill'},x))))));
 const pop=C.pyramid_of_pain,tiers=[['TTPs',pop.ttps,46],['Tools',pop.tools,58],['Artifacts',pop.artifacts,70],['Domains',pop.domains,80],['IPs',pop.ips,90],['Hashes',pop.hashes,100]];
 out.push(el('h2',{},'هرم درد'),el('div',{class:'card pyr'},...tiers.map(([n,a,w])=>el('div',{style:'width:'+w+'%'},el('b',{},n+' ('+a.length+')'),el('div',{class:'ltr dim',style:'font-size:11.5px'},a.slice(0,4).join(' | ')||'—')))));
 out.push(el('h2',{},'شاخص‌های نفوذ (IOC)'),el('div',{class:'grid g2'},...[['ips','🌐 IP'],['domains','🔗 دامنه'],['user_agents','🧰 User-Agent'],['hashes','#️⃣ هش'],['credentials','🔑 اعتبارنامه (ماسک)']].map(([k,l])=>el('div',{class:'card'},el('div',{class:'row'},el('h3',{style:'flex:1'},l+' ('+(D.iocs[k]||[]).length+')'),el('button',{class:'btn',onclick:()=>copy((D.iocs[k]||[]).join('\n'))},'کپی')),...(D.iocs[k]||[]).slice(0,80).map(x=>el('span',{class:'pill'},x))))));
 out.push(el('h2',{},'قوانین دفاعی'),el('div',{class:'grid g2'},...[['🦈 Wireshark',C.detection_arsenal.wireshark],['🛡️ Suricata',C.detection_arsenal.suricata],['🧬 YARA',C.detection_arsenal.yara],['🔎 Splunk / Elastic',C.detection_arsenal.splunk_spl+'\n\n'+C.detection_arsenal.elastic_kql]].map(([t,c])=>el('div',{class:'card'},el('div',{class:'row'},el('h3',{style:'flex:1'},t),el('button',{class:'btn',onclick:()=>copy(c)},'کپی')),el('pre',{},c)))));
 const rc=C.recommendations||{};out.push(el('h2',{},'نقشه راه پاسخ'),el('div',{class:'grid g3'},...[['immediate','🚨 فوری'],['short_term','🛠 کوتاه‌مدت'],['long_term','🏗 بلندمدت']].map(([k,l])=>el('div',{class:'card'},el('h3',{},l),el('ul',{},...(rc[k]||[]).map(x=>el('li',{},x)))))));return out});
// ============ STATS
reg('stats',0,()=>{const TOPS=D.tops;const bars=(rows,f)=>{f=f||String;const m=Math.max(...rows.map(r=>r[1]),1);return rows.map(([k,v])=>el('div',{class:'row',style:'margin:4px 0'},el('span',{class:'ltr',style:'width:46%;overflow:hidden'},String(k)),el('div',{class:'barbg',style:'flex:1'},el('div',{class:'bar',style:'width:'+(v/m*100)+'%'})),el('span',{class:'mono dim',style:'width:80px;text-align:end'},f(v))))};
 return [el('h2',{},'آمار تفصیلی'),el('div',{class:'grid g2'},...[['پورت‌های مقصد',TOPS.ports.map(p=>[p.port+' ('+p.service+')',p.packets])],['برترین ارتباطات',TOPS.talkers.map(t=>[t.src+' → '+t.dst,t.bytes]),hb],['DNS',TOPS.dns],['SNI',TOPS.sni],['میزبان HTTP',TOPS.http_hosts],['User-Agent',TOPS.uas],['بیشترین فرستنده‌ها',TOPS.senders,hb]].map(([t,r,f])=>el('div',{class:'card'},el('h3',{},t),...(r.length?bars(r,f):[el('div',{class:'empty'},'—')])))),
  D.tshark?el('div',{class:'card'},el('h3',{},'TShark'),el('pre',{},D.tshark)):null,
  el('div',{class:'card muted'},'موتور: '+(D.engine.fast_io?'پکت‌خوان بومی سریع':'scapy')+' · خطاها: '+D.engine.errors+(D.engine.read_error?' · '+D.engine.read_error:''))]});
// ============ chrome: header, nav, drawer
function build(){VIEWS.forEach(([id,ic,l])=>{nav.append(el('button',{'data-v':id,onclick:()=>go(id)},el('span',{},ic),l,id==='files'&&D.files.length?el('span',{class:'badge'},D.files.length):null,id==='findings'&&D.findings.length?el('span',{class:'badge'},D.findings.length):null))});
 nav.append(el('div',{class:'sep'}),el('button',{onclick:()=>{const n=LANGX==='fa'?'en':'fa';try{localStorage.setItem('pcaplang',n)}catch(e){}location.hash='lang='+n;location.reload()}},el('span',{},'🌐'),LANGX==='fa'?'English':'فارسی'),el('button',{onclick:()=>$('#drawer').classList.toggle('on')},el('span',{},'🎛️'),'تم و ظاهر'),el('button',{onclick:()=>{S.simple=S.simple?0:1;applyS()}},el('span',{},'🧒'),'حالت ساده'),el('button',{onclick:()=>window.print()},el('span',{},'🖨️'),'چاپ / PDF'));
 const dr=$('#drawer');dr.append(el('div',{class:'row'},el('h2',{style:'flex:1'},'🎛️ تم و ظاهر'),el('button',{class:'btn',onclick:()=>dr.classList.remove('on')},'✕')),el('h3',{style:'margin-top:10px'},'تم رنگی'));
 const sw=el('div',{class:'swatches'});Object.entries(D.themes).forEach(([id,t])=>sw.append(el('button',{class:'sw'+(S.theme===id?' on':''),'data-id':id,onclick:()=>{S.theme=id;applyS();sw.querySelectorAll('.sw').forEach(b=>b.classList.toggle('on',b.dataset.id===id))}},el('span',{},LANGX==='fa'?t.fa+' · '+t.name:t.name),(()=>{const i=el('i');[t.bg,t.acc,t.acc2,t.acc3,t.ok,t.bad].forEach(c=>i.append(el('b',{style:'background:'+c})));return i})())));dr.append(sw,el('h3',{style:'margin-top:14px'},'متریال (جنس پنل‌ها)'));
 const mt=el('div',{class:'row'});Object.entries(D.materials).forEach(([id,m])=>mt.append(el('button',{class:'btn'+(S.material===id?' on':''),'data-m':id,onclick:()=>{S.material=id;applyS();mt.querySelectorAll('.btn').forEach(b=>b.classList.toggle('on',b.dataset.m===id))}},LANGX==='fa'?m[1]:m[0])));dr.append(mt,el('h3',{style:'margin-top:14px'},'افکت‌ها'));
 [['grid','گرید سایبری'],['scan','اسکن‌لاین CRT'],['glow','درخشش نئونی'],['rain','باران ماتریکس'],['anim','انیمیشن‌ها']].forEach(([k,l])=>{const b=el('button',{class:'btn'+(S[k]?' on':''),onclick:()=>{S[k]=S[k]?0:1;b.classList.toggle('on',!!S[k]);applyS()}},S[k]?'روشن':'خاموش');dr.append(el('div',{class:'opt'},el('span',{},l),b))});
 const sel=el('select',{onchange:e=>{S.density=e.target.value;applyS()}},el('option',{value:'comfortable'},'راحت'),el('option',{value:'compact'},'فشرده'));sel.value=S.density;
 const fs=el('input',{type:'range',min:11,max:18,value:S.fs,oninput:e=>{S.fs=+e.target.value;applyS()}});
 const dirb=el('button',{class:'btn',onclick:()=>{S.dir=S.dir==='rtl'?'ltr':'rtl';S.dirFor=LANGX;applyS();dirb.textContent=S.dir==='rtl'?'راست‌به‌چپ':'چپ‌به‌راست'}},S.dir==='rtl'?'راست‌به‌چپ':'چپ‌به‌راست');
 dr.append(el('div',{class:'opt'},el('span',{},'تراکم'),sel),el('div',{class:'opt'},el('span',{},'اندازه متن'),fs),el('div',{class:'opt'},el('span',{},'جهت صفحه'),dirb),el('div',{class:'opt'},el('span',{},'بازنشانی'),el('button',{class:'btn',onclick:()=>{S=Object.assign({},DEF);applyS();location.reload()}},'پیش‌فرض')));
 const h=location.hash.slice(1).split('/');go(views[h[0]]?h[0]:'overview',h[1]?decodeURIComponent(h[1]):undefined)}
// matrix rain
let rainT=null;function rain(){const c=$('#rain'),x=c.getContext('2d');clearInterval(rainT);if(!S.rain||!S.anim)return;c.width=innerWidth;c.height=innerHeight;const cols=Math.floor(c.width/16),y=Array(cols).fill(0).map(()=>Math.random()*c.height/16),ch='01アイウエオカキクケコ{}<>/\\|$#@%';
 const col=getComputedStyle(document.documentElement).getPropertyValue('--acc').trim()||'#0f0';rainT=setInterval(()=>{x.fillStyle='rgba(0,0,0,.08)';x.fillRect(0,0,c.width,c.height);x.fillStyle=col;x.font='14px monospace';y.forEach((v,i)=>{x.fillText(ch[Math.floor(Math.random()*ch.length)],i*16,v*16);y[i]=v*16>c.height&&Math.random()>.975?0:v+1})},60)}
addEventListener('resize',()=>{if(S.rain)rain()});
applyS();build();
"""

def _i18n_js(js):
    """Wrap every Persian string literal of the report script in T() so the UI can switch language at runtime."""
    out, pos = [], 0
    for m in re.finditer(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*\"""", js):
        lit = m.group(0)
        if not re.search("[\u0600-\u06ff]", lit):
            continue
        prev = js[:m.start()].rstrip()[-1:]
        nxt = js[m.end():].lstrip()[:1]
        out.append(js[pos:m.start()])
        out.append(f"[T({lit})]" if (nxt == ":" and prev in "{,") else f"T({lit})")
        pos = m.end()
    out.append(js[pos:])
    return "".join(out)


JS = _i18n_js(JS_SRC)



def _jsonable(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def assemble_data(path, st, findings, corr, theme, material, defang=lambda x: x, plain_for=None, verdict=None, sev_fa=None, sev_color=None):
    hub = st.get("hub") or {}
    fl = []
    for f in findings:
        pf = plain_for(f["id"]) if plain_for else ("", "", "")
        if pf and pf[0].startswith("الگوی مشکوکی"):                     # rule without a hand-written plain text
            pf = (f.get("description_fa") or f.get("description", ""), "", f.get("recommendation_fa") or f.get("recommendation", ""))
        pen = (f.get("description_en") or "", "", f.get("recommendation_en") or "")
        fl.append(dict(f, plain=list(pf), plain_en=list(I18N.tr(x, "en") if i != 1 else x for i, x in enumerate(pen)) if any(pen) else None))
    iocs = {k: [defang(str(x)) for x in v][:400] for k, v in (corr.get("iocs") or {}).items()}
    tops = {
        "ports": st.get("top_ports", []), "talkers": st.get("top_talkers", []), "dns": st.get("top_dns", []),
        "sni": st.get("tls_sni", []), "http_hosts": st.get("http_hosts", []), "uas": st.get("http_user_agents", []),
        "senders": st.get("top_senders", []),
    }
    corr_slim = {k: corr[k] for k in ("executive_summary", "kill_chain", "diamond_model", "pyramid_of_pain", "detection_arsenal",
                                      "recommendations", "forensic_next_steps") if k in corr}
    for k in ("pyramid_of_pain", "diamond_model"):
        if k in corr_slim:
            corr_slim[k] = {a: [defang(str(x)) for x in b] for a, b in corr_slim[k].items()}
    lvl = corr.get("risk_level", "info")
    data = {
        "meta": {"lang": I18N.get_lang(), "app": META.APP_NAME, "version": META.VERSION, "author": META.AUTHOR, "repo": META.REPO_URL, "file": os.path.basename(path),
                 "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "theme": theme, "material": material, "start": st.get("start"), "end": st.get("end"),
                 "duration": st.get("duration_s", 0)},
        "risk": {"score": corr.get("risk_score", 0), "level": lvl, "level_fa": (sev_fa or {}).get(lvl, lvl), "confidence": corr.get("confidence_score", 0)},
        "verdict": list(verdict or ("🟢", "", "")),
        "stats": {"packets": st["packets"], "bytes": st["bytes"], "unique_ips": st["unique_ips"]},
        "timeline": st["timeline"], "themes": {k: v for k, v in TH.THEMES.items()}, "materials": TH.MATERIALS,
        "sev_fa": sev_fa or {}, "sev_color": sev_color or {},
        "protocols": hub.get("protocols", []), "events": hub.get("events", {}), "events_total": hub.get("events_total", {}),
        "flows": hub.get("flows", []), "flows_total": hub.get("flows_total", 0), "pairs": hub.get("pairs", []),
        "files": hub.get("files", []), "files_summary": hub.get("files_summary", {"zip": None, "count": 0, "bytes": 0, "mode": None, "by_category": {}, "risky": 0}),
        "findings_by_proto": hub.get("findings_by_proto", {}), "http_story": hub.get("http_story", []),
        "findings": fl, "corr": corr_slim, "iocs": iocs, "tops": tops, "tshark": "\n".join(st.get("tshark_phs") or []),
        "engine": st.get("engine", {"fast_io": False, "errors": 0, "read_error": None}),
    }
    data["ui"] = I18N.ui_table(data)
    return data


def build_cyber_report(path, st, findings, corr, theme=TH.DEFAULT_THEME, material=TH.DEFAULT_MATERIAL, **kw):
    data = assemble_data(path, st, findings, corr, theme, material, **kw)
    title = f"{META.APP_NAME} v{META.VERSION} — {os.path.basename(path)}"
    esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    _lang = I18N.get_lang()
    _dir = "rtl" if _lang == "fa" else "ltr"
    html = (
        f'<!doctype html><html lang="{_lang}" dir="{_dir}" data-lang="{_lang}" data-theme="{esc(theme)}" data-material="{esc(material)}" data-grid="1"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{esc(title)}</title><style>{TH.theme_css()}\n{CSS}</style></head><body>'
        '<div id="bg-grid"></div><canvas id="rain"></canvas><div id="bg-scan"></div>'
        '<div class="app"><header class="hdr panel"><div class="brand"><div class="logo">🛡️</div><div><h1>'
        f'{esc(META.APP_NAME)} <span class="chip acc">v{esc(META.VERSION)}</span></h1>'
        f'<div class="sub ltr">{esc(os.path.basename(path))} · <span class="l-en">generated {esc(data["meta"]["generated"])} · 100% offline</span><span class="l-fa">تولید: {esc(data["meta"]["generated"])} · ۱۰۰٪ آفلاین</span></div></div></div><div class="fill"></div>'
        f'<a class="chip" href="{esc(META.GITHUB_PROFILE)}" target="_blank" rel="noopener"><span class="l-en">Made with ♥ by {esc(META.AUTHOR)}</span><span class="l-fa">ساخته‌شده با ♥ توسط {esc(META.AUTHOR)}</span></a>'
        f'<a class="chip acc" href="{esc(META.REPO_URL)}" target="_blank" rel="noopener">GitHub</a></header>'
        '<nav class="nav panel" id="nav"></nav><main id="main"></main></div>'
        '<div class="ov" id="ov"><div class="modal-box" id="ovb"></div></div><aside class="drawer panel" id="drawer"></aside><div class="toast" id="toast"></div>'
        f'<script type="application/json" id="data">{_jsonable(data)}</script><script>{JS}</script></body></html>'
    )
    return html
