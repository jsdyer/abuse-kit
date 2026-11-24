import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseInput, registeredDomain, extractIPs, isPublicIP, parseDoh, parseDomainRdap, parseIpRdap, parseNetworkInfo,
  providerFor, contacts, draftReport, mailtoLink, groupByAsn, toCsv, ageInDays,
} from '../web/model.mjs';

const config = JSON.parse(readFileSync(new URL('../web/config.json', import.meta.url)));
const vcard = (fields) => ['vcard', fields.map(([k, v]) => [k, {}, 'text', v])];

test('config is usable', () => {
  assert.ok(config.bulk_limit > 0 && config.bulk_concurrency > 0 && config.max_addresses_per_target > 0);
  for (const [asn, p] of Object.entries(config.providers)) {
    assert.match(asn, /^\d+$/);
    assert.ok(['cdn', 'cloud'].includes(p.kind), asn);
    assert.match(p.report, /^(https:\/\/|mailto:)/, asn);
  }
});

test('parses domains, URLs and IPs', () => {
  assert.deepEqual(parseInput(' https://Login.Example.com/a?b=1 '), { kind: 'domain', value: 'login.example.com', url: 'https://login.example.com/a?b=1' });
  assert.deepEqual(parseInput('example.ca'), { kind: 'domain', value: 'example.ca', url: null });
  assert.deepEqual(parseInput('198.51.100.7'), { kind: 'ip', value: '198.51.100.7', url: null });
  assert.equal(parseInput('[2001:DB8::1]').value, '2001:db8::1');
  assert.equal(parseInput('http://192.0.2.5/x').kind, 'ip');
  for (const bad of ['', 'not a domain', 'ftp://example.com', 'localhost']) assert.throws(() => parseInput(bad), bad);
});

test('registered domain', () => {
  assert.equal(registeredDomain('a.b.example.co.uk', config.multi_label_suffixes), 'example.co.uk');
  assert.equal(registeredDomain('www.example.ca', config.multi_label_suffixes), 'example.ca');
});

test('extracts unique IPs from log lines and respects the limit', () => {
  const text = '8.8.8.8 - - [x] "GET /"\nfrom 2606:4700::1111, again 8.8.8.8 and 1.1.1.1.\n999.1.1.1 12:30:45';
  assert.deepEqual(extractIPs(text, 10), { ips: ['8.8.8.8', '2606:4700::1111', '1.1.1.1'], truncated: false });
  assert.deepEqual(extractIPs(text, 2), { ips: ['8.8.8.8', '2606:4700::1111'], truncated: true });
  const many = Array.from({ length: 700 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`).join('\n');
  assert.equal(extractIPs(many, 600).ips.length, 600);
});

test('public address check', () => {
  for (const ip of ['8.8.8.8', '203.0.114.1', '2606:4700::1']) assert.ok(isPublicIP(ip), ip);
  for (const ip of ['10.1.1.1', '192.168.0.1', '172.20.0.1', '127.0.0.1', '203.0.113.9', '198.51.100.1', '100.64.0.1', 'fe80::1', '2001:db8::1']) assert.ok(!isPublicIP(ip), ip);
});

test('parses DNS and RDAP', () => {
  assert.deepEqual(parseDoh({ Status: 0, Answer: [{ type: 2, data: 'NS1.Example.NET.' }, { type: 1, data: '1.2.3.4' }] }, 'NS'), { rcode: 'NOERROR', values: ['ns1.example.net'] });
  const domain = parseDomainRdap({
    status: ['client transfer prohibited'], events: [{ eventAction: 'registration', eventDate: '2026-11-01T00:00:00Z' }],
    nameservers: [{ ldhName: 'NS1.HOST.EXAMPLE' }],
    entities: [{ roles: ['registrar'], publicIds: [{ type: 'IANA Registrar ID', identifier: '1068' }], vcardArray: vcard([['fn', 'NameCheap, Inc.']]),
      entities: [{ roles: ['abuse'], vcardArray: vcard([['email', 'abuse@namecheap.com']]) }] }],
  });
  assert.deepEqual(domain, { registrar: 'NameCheap, Inc.', registrarIanaId: '1068', abuse: 'abuse@namecheap.com',
    statuses: ['client transfer prohibited'], registered: '2026-11-01T00:00:00Z', expires: null, nameservers: ['ns1.host.example'] });
  const ip = parseIpRdap({ name: 'HOST-NET', startAddress: '1.2.3.0', endAddress: '1.2.3.255', country: 'US',
    entities: [{ roles: ['registrant'], vcardArray: vcard([['fn', 'Host Inc']]), entities: [{ roles: ['abuse'], vcardArray: vcard([['email', 'mailto:abuse@host.example']]) }] }] });
  assert.equal(ip.abuse, 'abuse@host.example');
  assert.equal(ip.organization, 'Host Inc');
  assert.deepEqual(parseNetworkInfo({ data: { asns: ['13335'], prefix: '104.16.0.0/13' } }), { asns: ['13335'], prefix: '104.16.0.0/13' });
  assert.throws(() => parseNetworkInfo({}));
});

test('contacts put the CDN and registrar first and skip CDN network contacts', () => {
  const list = contacts({
    domain: { registrar: 'NameCheap, Inc.', abuse: 'abuse@namecheap.com' },
    addresses: [
      { ip: '104.16.1.1', asns: ['13335'], abuse: 'abuse@cloudflare.com' },
      { ip: '5.6.7.8', asns: ['64500'], abuse: 'abuse@smallhost.example', organization: 'Small Host' },
      { ip: '5.6.7.9', asns: ['64500'], abuse: 'abuse@smallhost.example', organization: 'Small Host' },
    ],
    providers: config.providers,
  });
  assert.deepEqual(list.map(c => [c.role, c.contact]), [
    ['CDN / proxy', 'https://abuse.cloudflare.com/'],
    ['Registrar', 'mailto:abuse@namecheap.com'],
    ['Network operator', 'mailto:abuse@smallhost.example'],
  ]);
  assert.equal(providerFor('AS16509', config.providers).kind, 'cloud');
  assert.equal(providerFor('64500', config.providers), null);
});

test('draft report includes the evidence and suits the recipient', () => {
  const draft = draftReport({
    target: { kind: 'domain', value: 'login.example.com', url: 'https://login.example.com/a' }, kind: 'phishing', brand: 'Example Bank',
    evidence: 'urlscan: https://urlscan.io/result/x/\nSMS received 2026-11-23', reporter: 'Jeffrey', observedAt: '2026-11-24 05:00:00 UTC',
    domain: { registrar: 'NameCheap, Inc.', registrarIanaId: '1068', registered: '2026-11-01T00:00:00Z', nameservers: ['ns1.host.example'] },
    addresses: [{ ip: '5.6.7.8', asns: ['64500'], holder: 'SMALLHOST', prefix: '5.6.7.0/24' }],
    recipient: { role: 'Registrar', name: 'NameCheap, Inc.', contact: 'mailto:abuse@namecheap.com' },
  });
  assert.equal(draft.subject, 'Abuse report: a phishing site at login.example.com');
  for (const piece of ['impersonating Example Bank', 'https://login.example.com/a', 'IANA ID 1068', 'AS64500 SMALLHOST', '  SMS received', 'suspend the domain', 'Jeffrey']) {
    assert.ok(draft.body.includes(piece), piece);
  }
  const link = mailtoLink({ contact: 'mailto:abuse@namecheap.com' }, draft);
  assert.ok(link.startsWith('mailto:abuse@namecheap.com?subject=Abuse%20report'));
  assert.equal(mailtoLink({ contact: 'https://abuse.cloudflare.com/' }, draft), null);
});

test('groups and exports bulk results safely', () => {
  const rows = [
    { ip: '1.1.1.1', asns: ['13335'], holder: 'CLOUDFLARENET', prefix: '1.1.1.0/24', abuse: 'abuse@cloudflare.com' },
    { ip: '1.0.0.1', asns: ['13335'], holder: 'CLOUDFLARENET', prefix: '1.0.0.0/24' },
    { ip: '8.8.8.8', asns: ['15169'], holder: '=HYPERLINK("x")' },
    { ip: '10.0.0.1', asns: [], error: 'private or reserved address' },
  ];
  const groups = groupByAsn(rows.filter(r => r.asns.length));
  assert.deepEqual(groups.map(g => [g.asn, g.ips.length, g.abuse]), [['AS13335', 2, 'abuse@cloudflare.com'], ['AS15169', 1, null]]);
  const csv = toCsv(rows);
  assert.ok(csv.startsWith('ip,asn,holder,prefix,abuse_contact,error\n'));
  assert.ok(csv.includes(`"'=HYPERLINK(""x"")"`));
  assert.equal(csv.trim().split('\n').length, 5);
});

test('domain age', () => {
  assert.equal(ageInDays('2026-11-01T00:00:00Z', new Date('2026-11-24T00:00:00Z')), 23);
  assert.equal(ageInDays(null), null);
});
