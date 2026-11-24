// Pure functions for Abuse Kit. No DOM or network access here.

const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isIPv4(text) { return IPV4.test(text); }

export function isIPv6(text) {
  if (!/^[0-9a-f:.]+$/i.test(text) || !text.includes(':')) return false;
  try { return new URL(`http://[${text}]/`).hostname.length > 2; } catch { return false; }
}

export function isIP(text) { return isIPv4(text) || isIPv6(text); }

// Private, loopback, link-local, documentation and other non-public IPv4 ranges.
export function isPublicIPv4(ip) {
  const [a, b, c] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
}

export function isPublicIP(ip) {
  if (isIPv4(ip)) return isPublicIPv4(ip);
  if (!isIPv6(ip)) return false;
  const lower = ip.toLowerCase();
  return /^[23]/.test(lower) && !lower.startsWith('2001:db8');
}

export function parseInput(input) {
  const raw = String(input ?? '').trim();
  if (!raw) throw new Error('Enter a domain, URL or IP address');
  const bare = raw.replace(/^\[|\]$/g, '');
  if (isIP(bare)) return { kind: 'ip', value: bare.toLowerCase(), url: null };
  let url;
  try {
    url = new URL(raw.includes('://') ? raw : `https://${raw}`);
  } catch {
    throw new Error('That is not a valid domain, URL or IP address');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use an http or https URL');
  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (isIP(host)) return { kind: 'ip', value: host, url: raw.includes('://') ? url.href : null };
  if (!HOST.test(host)) throw new Error('That is not a valid domain name');
  return { kind: 'domain', value: host, url: raw.includes('://') ? url.href : null };
}

export function registeredDomain(host, suffixes = []) {
  const labels = host.split('.');
  if (labels.length >= 3 && suffixes.includes(labels.slice(-2).join('.'))) return labels.slice(-3).join('.');
  return labels.slice(-2).join('.');
}

export function extractIPs(text, limit) {
  const found = [];
  const seen = new Set();
  const candidates = String(text ?? '').match(/[0-9a-fA-F:.]{7,45}/g) ?? [];
  let truncated = false;
  for (const candidate of candidates) {
    const ip = candidate.replace(/^[:.]+|[:.]+$/g, '');
    if (!isIP(ip) || seen.has(ip.toLowerCase())) continue;
    if (found.length >= limit) { truncated = true; break; }
    seen.add(ip.toLowerCase());
    found.push(ip.toLowerCase());
  }
  return { ips: found, truncated };
}

export function parseDoh(data, type) {
  if (!data || typeof data.Status !== 'number') throw new Error('Unexpected DNS response');
  const rcode = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' }[data.Status] ?? `RCODE${data.Status}`;
  const wanted = { A: 1, AAAA: 28, NS: 2 }[type];
  const values = (data.Answer ?? []).filter(a => a.type === wanted).map(a => String(a.data).replace(/\.$/, '').toLowerCase());
  return { rcode, values: [...new Set(values)].sort() };
}

function vcard(entity, field) {
  const card = entity?.vcardArray?.[1];
  if (!Array.isArray(card)) return null;
  const item = card.find(entry => Array.isArray(entry) && entry[0] === field);
  if (!item) return null;
  const value = Array.isArray(item[3]) ? item[3].filter(Boolean).join(' ') : item[3];
  return value ? String(value) : null;
}

function* entities(list, role) {
  for (const entity of list ?? []) {
    if (!entity || typeof entity !== 'object') continue;
    if (!role || entity.roles?.includes(role)) yield entity;
    yield* entities(entity.entities, role);
  }
}

function abuseEmail(list) {
  for (const entity of entities(list, 'abuse')) {
    const email = vcard(entity, 'email');
    if (email) return email.replace(/^mailto:/i, '');
  }
  return null;
}

export function parseDomainRdap(data) {
  const registrar = entities(data?.entities, 'registrar').next().value;
  const events = Object.fromEntries((data?.events ?? []).map(e => [e.eventAction, e.eventDate]));
  const ianaId = registrar?.publicIds?.find(p => /iana/i.test(p.type ?? ''))?.identifier ?? null;
  return {
    registrar: registrar ? vcard(registrar, 'fn') : null,
    registrarIanaId: ianaId,
    abuse: registrar ? abuseEmail(registrar.entities) : null,
    statuses: [...new Set((data?.status ?? []).map(s => String(s).toLowerCase()))].sort(),
    registered: events.registration ?? null,
    expires: events.expiration ?? null,
    nameservers: [...new Set((data?.nameservers ?? []).map(n => String(n?.ldhName ?? '').toLowerCase()).filter(Boolean))].sort(),
  };
}

export function parseIpRdap(data) {
  const registrant = entities(data?.entities, 'registrant').next().value;
  return {
    network: data?.name ?? null,
    handle: data?.handle ?? null,
    range: data?.startAddress && data?.endAddress ? `${data.startAddress} – ${data.endAddress}` : null,
    country: data?.country ?? null,
    organization: registrant ? vcard(registrant, 'fn') : null,
    abuse: abuseEmail(data?.entities),
  };
}

export function parseNetworkInfo(data) {
  const info = data?.data;
  if (!info || !Array.isArray(info.asns)) throw new Error('Unexpected RIPEstat response');
  return { asns: info.asns.map(String), prefix: info.prefix ?? null };
}

export function parseAsOverview(data) {
  return data?.data?.holder ?? null;
}

export function providerFor(asn, providers) {
  const entry = providers?.[String(asn ?? '').replace(/^AS/i, '')];
  return entry ? { asn: `AS${String(asn).replace(/^AS/i, '')}`, ...entry } : null;
}

export function ageInDays(iso, now = new Date()) {
  const time = Date.parse(iso);
  return Number.isFinite(time) ? Math.floor((now - time) / 86_400_000) : null;
}

// Who to contact, in the order most likely to get a fast result.
export function contacts({ domain, addresses = [], providers = {} }) {
  const list = [];
  const seen = new Set();
  const add = (entry) => {
    const key = `${entry.role}|${entry.contact}`;
    if (!entry.contact || seen.has(key)) return;
    seen.add(key);
    list.push(entry);
  };
  for (const address of addresses) {
    const provider = address.asns.map(asn => providerFor(asn, providers)).find(Boolean);
    if (provider?.kind === 'cdn') {
      add({ role: 'CDN / proxy', name: provider.name, contact: provider.report, why: provider.note ?? `${provider.asn} is a CDN in front of the real host.` });
    }
  }
  if (domain?.registrar) {
    add({ role: 'Registrar', name: domain.registrar, contact: domain.abuse ? `mailto:${domain.abuse}` : null,
      why: 'Can suspend the domain itself, which stops it everywhere.' });
  }
  for (const address of addresses) {
    const provider = address.asns.map(asn => providerFor(asn, providers)).find(Boolean);
    if (provider?.kind === 'cloud') {
      add({ role: 'Hosting provider', name: provider.name, contact: provider.report, why: `Operates ${address.ip} (${provider.asn}).` });
    }
    if (address.abuse && provider?.kind !== 'cdn') {
      add({ role: 'Network operator', name: address.organization ?? address.network ?? address.holder ?? address.ip,
        contact: `mailto:${address.abuse}`, why: `Abuse contact for ${address.ip}${address.asns[0] ? ` (AS${address.asns[0]})` : ''} in the registry record.` });
    }
  }
  return list;
}

export const ABUSE_TYPES = {
  phishing: 'a phishing site',
  scam: 'a fraudulent (scam) site',
  malware: 'malware distribution',
  impersonation: 'brand impersonation',
  spam: 'spam',
  other: 'abuse',
};

export function draftReport({ target, kind = 'phishing', brand = '', evidence = '', reporter = '', observedAt, domain, addresses = [], recipient }) {
  const what = ABUSE_TYPES[kind] ?? ABUSE_TYPES.other;
  const lines = [];
  const subject = `Abuse report: ${what} at ${target.value}`;
  lines.push(`Hello${recipient?.name ? ` ${recipient.name} abuse team` : ''},`, '');
  lines.push(`I am reporting ${what}${brand ? ` impersonating ${brand}` : ''} at:`, '');
  lines.push(`  ${target.url ?? target.value}`, '');
  lines.push(`Observed: ${observedAt}`);
  if (domain?.registrar) lines.push(`Registrar: ${domain.registrar}${domain.registrarIanaId ? ` (IANA ID ${domain.registrarIanaId})` : ''}`);
  if (domain?.registered) lines.push(`Domain registered: ${domain.registered.slice(0, 10)}`);
  if (domain?.nameservers?.length) lines.push(`Nameservers: ${domain.nameservers.join(', ')}`);
  for (const address of addresses) {
    lines.push(`Resolves to: ${address.ip}${address.asns.length ? ` (AS${address.asns.join(', AS')}${address.holder ? ` ${address.holder}` : ''})` : ''}${address.prefix ? `, prefix ${address.prefix}` : ''}`);
  }
  if (evidence.trim()) lines.push('', 'Evidence:', ...evidence.trim().split(/\r?\n/).map(line => `  ${line}`));
  lines.push('', recipient?.role === 'Registrar'
    ? 'Please suspend the domain under your abuse policy.'
    : 'Please take the content down or suspend the service under your abuse policy.');
  lines.push('', 'Thank you,', reporter.trim() || '[your name]');
  return { subject, body: lines.join('\n') };
}

export function mailtoLink(recipient, draft) {
  if (!recipient?.contact?.startsWith('mailto:')) return null;
  const address = recipient.contact.slice('mailto:'.length);
  return `mailto:${address}?subject=${encodeURIComponent(draft.subject)}&body=${encodeURIComponent(draft.body)}`;
}

export function groupByAsn(rows) {
  const groups = new Map();
  for (const row of rows) {
    const key = row.asns[0] ?? 'none';
    const group = groups.get(key) ?? { asn: row.asns[0] ? `AS${row.asns[0]}` : null, holder: row.holder ?? null, abuse: row.abuse ?? null, ips: [] };
    group.ips.push(row.ip);
    group.holder ??= row.holder ?? null;
    group.abuse ??= row.abuse ?? null;
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => b.ips.length - a.ips.length || String(a.asn).localeCompare(String(b.asn)));
}

function csvField(value) {
  const text = String(value ?? '');
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCsv(rows) {
  const header = ['ip', 'asn', 'holder', 'prefix', 'abuse_contact', 'error'];
  const lines = [header.join(',')];
  for (const row of rows) {
    lines.push([row.ip, row.asns?.length ? `AS${row.asns.join(' AS')}` : '', row.holder, row.prefix, row.abuse, row.error].map(csvField).join(','));
  }
  return lines.join('\n') + '\n';
}
