#!/usr/bin/env node
/*
 * llabyrinth — jsdom real-click smoke test for the `web` export.
 *
 * Generates two exports with the real CLI (sample scan with an attack
 * path, and an adversarial scan full of XSS payloads), opens them in
 * jsdom, and simulates user actions: graph renders → click host node →
 * detail panel fills → click port node → search dims non-matches →
 * path highlight is present. For the evil export: payloads must exist
 * only as inert text — no injected elements.
 *
 * Setup: cd tests && npm install   (dev-only; the tool stays stdlib)
 * Run:   node tests/web-smoke.js
 */
'use strict';

var fs = require('fs');
var os = require('os');
var path = require('path');
var childProcess = require('child_process');
var JSDOM = require('jsdom').JSDOM;

var ROOT = path.join(__dirname, '..');
var BIN = path.join(ROOT, 'llabyrinth.py');
var SAMPLE = path.join(ROOT, 'examples', 'scan-sample.xml');

var failures = 0;
function check(name, cond, extra) {
  if (cond) console.log('  ok  ' + name);
  else { failures++; console.log('FAIL  ' + name + (extra ? ' -- ' + extra : '')); }
}
function waitFor(fn, timeoutMs, label) {
  var start = Date.now();
  return new Promise(function (resolve, reject) {
    (function poll() {
      var v;
      try { v = fn(); } catch (e) { v = null; }
      if (v) return resolve(v);
      if (Date.now() - start > timeoutMs) return reject(new Error('timeout: ' + label));
      setTimeout(poll, 60);
    })();
  });
}
function genExport(args, outName) {
  var out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'llab-')), outName);
  var r = childProcess.spawnSync('python3', [BIN].concat(args, ['-o', out]),
    { encoding: 'utf-8' });
  if (r.status !== 0) throw new Error('CLI failed: ' + r.stderr);
  return out;
}
function nodeById(window, id) {
  return window.document.querySelector('.node[data-node-id="' + id + '"]');
}
function click(window, el) {
  el.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
}

async function main() {
  /* ---- export 1: sample scan + attack path ---- */
  var htmlPath = genExport(
    ['web', '--from-nmap', SAMPLE, '--from', '192.168.1.1',
     '--to', '192.168.1.20:3306/tcp'], 'peta.html');
  var dom = await JSDOM.fromFile(htmlPath, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true
  });
  var window = dom.window;
  await waitFor(function () {
    return window.document.querySelectorAll('#graph .node').length > 0;
  }, 8000, 'graph nodes render');
  var nodes = window.document.querySelectorAll('#graph .node');
  check('sample export renders 27 nodes (3 subnet + 7 host + 17 port)',
    nodes.length === 27, 'got ' + nodes.length);

  var strip = window.document.getElementById('path-strip');
  check('path strip visible with summary',
    strip.hidden === false && strip.textContent.indexOf('3306/tcp') !== -1,
    strip.textContent);
  var pathEdges = window.document.querySelectorAll('#graph line.edge.path');
  check('path edges highlighted (3)', pathEdges.length === 3,
    'got ' + pathEdges.length);
  var pathNodes = window.document.querySelectorAll('#graph .node.onpath');
  check('path nodes highlighted (4)', pathNodes.length === 4,
    'got ' + pathNodes.length);

  var hostEl = nodeById(window, '192.168.1.20');
  check('webserver host node exists', !!hostEl);
  click(window, hostEl);
  var title = window.document.getElementById('detail-title').textContent;
  var body = window.document.getElementById('detail-body').textContent;
  check('click host → detail title is hostname', title === 'webserver.lan', title);
  check('detail shows full port table incl. MySQL row',
    body.indexOf('3306/tcp') !== -1 && body.indexOf('MySQL') !== -1);
  check('detail shows closed ssh too (uncapped table)',
    body.indexOf('22/tcp') !== -1 && body.indexOf('closed') !== -1);
  check('detail shows entity-decoded script output as text',
    body.indexOf('Example <b>Portal</b>') !== -1);
  check('no <b> element was created from script output',
    window.document.querySelectorAll('#detail-body b').length === 0);

  var portEl = nodeById(window, '192.168.1.20:3306/tcp');
  click(window, portEl);
  title = window.document.getElementById('detail-title').textContent;
  body = window.document.getElementById('detail-body').textContent;
  check('click port → detail title 3306/tcp', title === '3306/tcp', title);
  check('port detail shows product/version',
    body.indexOf('MySQL') !== -1 && body.indexOf('8.0.28') !== -1);

  var search = window.document.getElementById('search');
  search.value = 'postgresql';
  search.dispatchEvent(new window.Event('input', { bubbles: true }));
  var dbHost = nodeById(window, '10.0.0.5');
  var wsHost = nodeById(window, '192.168.1.20');
  check('search: matching host stays bright', !dbHost.classList.contains('dim'));
  check('search: non-matching host dims', wsHost.classList.contains('dim'));
  search.value = '';
  search.dispatchEvent(new window.Event('input', { bubbles: true }));
  check('search cleared → nothing dimmed',
    !wsHost.classList.contains('dim') && !dbHost.classList.contains('dim'));
  window.close();

  /* ---- export 2: adversarial scan ---- */
  var evilXml = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'llab-')), 'evil.xml');
  fs.writeFileSync(evilXml,
    '<nmaprun scanner="nmap" version="7.94"><host>' +
    '<status state="up" reason="echo-reply"/>' +
    '<address addr="10.6.6.6" addrtype="ipv4"/>' +
    '<hostnames><hostname name="&lt;script&gt;alert(1)&lt;/script&gt;" type="PTR"/></hostnames>' +
    '<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>' +
    '<service name="http" product="&quot;&gt;&lt;img src=x onerror=alert(2)&gt;" version="1.0"/>' +
    '<script id="http-title" output="&lt;/title&gt;&lt;svg onload=alert(3)&gt;"/>' +
    '</port></ports></host></nmaprun>');
  var evilPath = genExport(['web', '--from-nmap', evilXml], 'evil.html');
  var dom2 = await JSDOM.fromFile(evilPath, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true
  });
  var w2 = dom2.window;
  await waitFor(function () {
    return w2.document.querySelectorAll('#graph .node').length > 0;
  }, 8000, 'evil graph renders');
  check('evil export: exactly the 2 template script tags exist',
    w2.document.querySelectorAll('script').length === 2,
    'got ' + w2.document.querySelectorAll('script').length);
  check('evil export: no img elements anywhere',
    w2.document.querySelectorAll('img').length === 0);
  check('evil export: no svg onload attribute injected',
    w2.document.querySelectorAll('[onload]').length === 0);
  var evilHost = nodeById(w2, '10.6.6.6');
  check('evil host node label is the payload, as text',
    evilHost.textContent.indexOf('<script>alert(1)</script>') !== -1);
  click(w2, evilHost);
  var ebody = w2.document.getElementById('detail-body');
  check('evil host detail contains payload banner as text',
    ebody.textContent.indexOf('"><img src=x onerror=alert(2)>') !== -1);
  check('evil host detail contains zero img/script elements',
    ebody.querySelectorAll('img,script').length === 0);
  w2.close();

  console.log(failures === 0 ? '\nSMOKE OK' : '\nSMOKE FAILED: ' + failures);
  process.exit(failures ? 1 : 0);
}

main().catch(function (e) {
  console.log('SMOKE ERROR: ' + e.message);
  process.exit(1);
});
