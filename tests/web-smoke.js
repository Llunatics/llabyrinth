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

  /* ---- remediation simulator (llabyss) ---- */
  var remedStrip = window.document.getElementById('remed-strip');
  var btnPatch = window.document.getElementById('btn-patch');
  check('remediation strip visible with baseline risk',
    remedStrip.hidden === false &&
    remedStrip.textContent.indexOf('Risk 74') !== -1 &&
    remedStrip.textContent.indexOf('20/27') !== -1 &&
    remedStrip.textContent.indexOf('3 hops') !== -1 &&
    remedStrip.textContent.indexOf('patched 0') !== -1,
    remedStrip.textContent);
  check('patch mode button enabled', btnPatch.disabled === false);
  click(window, btnPatch);
  check('patch mode toggles on',
    btnPatch.textContent === 'Patch mode: on' &&
    btnPatch.classList.contains('active'));

  var midHost = nodeById(window, '192.168.1.20');
  click(window, midHost);
  midHost = nodeById(window, '192.168.1.20');
  check('patch mode: click mid-path host patches it',
    midHost.classList.contains('patched'));
  check('patching mid host isolates the target',
    strip.textContent.indexOf('Target isolated') !== -1 &&
    strip.classList.contains('isolated'));
  check('risk drops after isolating patch (36, 16/27)',
    remedStrip.textContent.indexOf('Risk 36') !== -1 &&
    remedStrip.textContent.indexOf('16/27') !== -1 &&
    remedStrip.textContent.indexOf('isolated') !== -1 &&
    remedStrip.textContent.indexOf('patched 1') !== -1,
    remedStrip.textContent);
  check('no path edges left after isolating patch',
    window.document.querySelectorAll('#graph line.edge.path').length === 0);

  click(window, midHost);
  midHost = nodeById(window, '192.168.1.20');
  check('click patched node again unpatches it',
    !midHost.classList.contains('patched'));
  check('path strip restored after unpatch',
    strip.textContent.indexOf('Attack path (3 hops)') !== -1 &&
    !strip.classList.contains('isolated'));
  check('risk restored after unpatch',
    remedStrip.textContent.indexOf('Risk 74') !== -1);

  var port80 = nodeById(window, '192.168.1.20:80/tcp');
  click(window, port80);
  port80 = nodeById(window, '192.168.1.20:80/tcp');
  check('patching off-path port keeps the path, shrinks surface',
    port80.classList.contains('patched') &&
    strip.textContent.indexOf('Attack path (3 hops)') !== -1 &&
    remedStrip.textContent.indexOf('Risk 72') !== -1 &&
    remedStrip.textContent.indexOf('19/27') !== -1,
    remedStrip.textContent);

  var srcHost = nodeById(window, '192.168.1.1');
  click(window, srcHost);
  srcHost = nodeById(window, '192.168.1.1');
  check('entry point cannot be patched',
    !srcHost.classList.contains('patched') &&
    remedStrip.textContent.indexOf('patched 1') !== -1);
  var subnet = nodeById(window, 'subnet:192.168.1.0/24');
  click(window, subnet);
  subnet = nodeById(window, 'subnet:192.168.1.0/24');
  check('subnet container cannot be patched',
    !subnet.classList.contains('patched'));

  click(window, window.document.getElementById('btn-reset-patches'));
  port80 = nodeById(window, '192.168.1.20:80/tcp');
  check('reset patches restores baseline',
    !port80.classList.contains('patched') &&
    remedStrip.textContent.indexOf('Risk 74') !== -1 &&
    remedStrip.textContent.indexOf('patched 0') !== -1);

  click(window, btnPatch);
  check('patch mode toggles off', btnPatch.textContent === 'Patch mode: off');
  var host20 = nodeById(window, '192.168.1.20');
  click(window, host20);
  var patchBtn = window.document.querySelector('.patch-btn');
  check('detail panel offers Patch button in inspect mode',
    !!patchBtn && patchBtn.textContent === 'Patch this node');
  click(window, patchBtn);
  host20 = nodeById(window, '192.168.1.20');
  check('detail Patch button patches the node',
    host20.classList.contains('patched'));
  patchBtn = window.document.querySelector('.patch-btn');
  check('detail button flips to Remove patch',
    !!patchBtn && patchBtn.textContent === 'Remove patch');
  click(window, patchBtn);
  host20 = nodeById(window, '192.168.1.20');
  check('detail Remove patch unpatches the node',
    !host20.classList.contains('patched'));
  window.close();

  /* ---- export 1b: folded ports — risk parity CLI vs browser ---- */
  function foldHost(ip, mac, name, ports) {
    var ps = ports.map(function (p) {
      return '<port protocol="tcp" portid="' + p + '"><state state="open"/>' +
        '<service name="svc' + p + '"/></port>';
    }).join('');
    return '<host><status state="up"/><address addr="' + ip + '" addrtype="ipv4"/>' +
      '<address addr="' + mac + '" addrtype="mac"/>' +
      '<hostnames><hostname name="' + name + '" type="PTR"/></hostnames>' +
      '<ports>' + ps + '</ports></host>';
  }
  var foldPorts20 = [];
  for (var i = 1000; i < 1035; i++) foldPorts20.push(i);
  foldPorts20[5] = 3306; // target jadi port terakhir (terlipat tanpa exemption)
  var foldPorts9 = [];
  for (var j = 2000; j < 2200; j++) foldPorts9.push(j);
  var foldXml = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'llab-')), 'fold.xml');
  fs.writeFileSync(foldXml,
    '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94" ' +
    'args="nmap -oX - 192.168.1.0/24 10.0.0.0/24">' +
    foldHost('192.168.1.1', 'AA:BB:CC:00:00:01', 'router.lan', [80]) +
    foldHost('192.168.1.20', 'AA:BB:CC:00:00:02', 'webserver.lan', foldPorts20) +
    foldHost('10.0.0.9', 'AA:BB:CC:00:00:09', 'db2.lan', foldPorts9) +
    '<runstats><finished summary="done"/></runstats></nmaprun>');
  var cliRisk = childProcess.spawnSync('python3',
    [BIN, 'paths', '--from-nmap', foldXml, '--from', '192.168.1.1',
     '--to', '192.168.1.20:3306/tcp', '--json'], { encoding: 'utf-8' });
  if (cliRisk.status !== 0) throw new Error('CLI risk failed: ' + cliRisk.stderr);
  var cli = JSON.parse(cliRisk.stdout).risk;
  var foldHtml = genExport(
    ['web', '--from-nmap', foldXml, '--from', '192.168.1.1',
     '--to', '192.168.1.20:3306/tcp'], 'fold.html');
  var foldDom = await JSDOM.fromFile(foldHtml, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true
  });
  var fw = foldDom.window;
  await waitFor(function () {
    return fw.document.querySelectorAll('#graph .node').length > 0;
  }, 8000, 'folded graph nodes render');
  var foldStrip = fw.document.getElementById('remed-text').textContent;
  var foldPath = fw.document.getElementById('path-strip').textContent;
  check('folded scan: browser risk/surface = CLI risk/surface',
    foldStrip.indexOf('Risk ' + cli.risk) !== -1 &&
    foldStrip.indexOf(cli.reachable + '/' + cli.total) !== -1,
    foldStrip + ' vs CLI ' + JSON.stringify(cli));
  check('folded target port is drawn (not swallowed by +N ports)',
    !!nodeById(fw, '192.168.1.20:3306/tcp'));
  check('path strip names the real target port, not the aggregate',
    foldPath.indexOf('3306/tcp') !== -1 &&
    foldPath.indexOf('+4 ports') === -1,
    foldPath);
  var foldMore = nodeById(fw, '192.168.1.20/more');
  click(fw, foldMore);
  check('aggregated ports node says it cannot be patched individually',
    fw.document.getElementById('detail-body').textContent
      .indexOf('cannot patch individually') !== -1);
  foldDom.window.close();

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

  /* ---- export 3: no --from/--to → remediation disabled ---- */
  var noPath = genExport(['web', '--from-nmap', SAMPLE], 'no-remed.html');
  var dom3 = await JSDOM.fromFile(noPath, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true
  });
  var w3 = dom3.window;
  await waitFor(function () {
    return w3.document.querySelectorAll('#graph .node').length > 0;
  }, 8000, 'no-remed graph renders');
  check('no --from/--to: patch button disabled',
    w3.document.getElementById('btn-patch').disabled === true);
  check('no --from/--to: remediation strip hidden',
    w3.document.getElementById('remed-strip').hidden === true);
  check('no --from/--to: path strip hidden',
    w3.document.getElementById('path-strip').hidden === true);
  w3.close();

  console.log(failures === 0 ? '\nSMOKE OK' : '\nSMOKE FAILED: ' + failures);
  process.exit(failures ? 1 : 0);
}

main().catch(function (e) {
  console.log('SMOKE ERROR: ' + e.message);
  process.exit(1);
});
