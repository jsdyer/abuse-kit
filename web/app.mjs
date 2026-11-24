import {
  parseInput, registeredDomain, extractIPs, parseDoh, parseDomainRdap, parseIpRdap, parseNetworkInfo,
  parseAsOverview, isPublicIP, contacts, ABUSE_TYPES, draftReport, mailtoLink, groupByAsn, toCsv, ageInDays, providerFor, selectRecipient,
} from './model.mjs';

const $ = selector => document.querySelector(selector);
let config = null;
let current = null; // { target, domain, addresses, contacts, observedAt }
let bulkRun = 0;
let lookupRun = 0;
let csvUrl = null;

function el(tag, text, attrs = {}) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function fact(list, term, value) {
  if (value == null || value === '' || (Array.isArray(value) && !value.length)) return;
  list.append(el('dt', term), el('dd', Array.isArray(value) ? value.join(', ') : String(value)));
}

const utc = date => date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

async function getJson(url, accept = 'application/json') {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, { headers: { Accept: accept }, credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); }
}

const stat = (endpoint, resource) =>
  `https://stat.ripe.net/data/${endpoint}/data.json?resource=${encodeURIComponent(resource)}&sourceapp=${encodeURIComponent(config.ripestat_sourceapp)}`;

const holders = new Map();
async function holderFor(asn) {
  if (!asn) return null;
  if (!holders.has(asn)) holders.set(asn, getJson(stat('as-overview', `AS${asn}`)).then(parseAsOverview).catch(() => null));
  return holders.get(asn);
}

async function describeAddress(ip) {
  if (!isPublicIP(ip)) return { ip, asns: [], error: 'private or reserved address; not sent for lookup' };
  const errors = [];
  const [network, rdap] = await Promise.all([
    getJson(stat('network-info', ip)).then(parseNetworkInfo).catch(() => { errors.push('Network lookup unavailable'); return { asns: [], prefix: null }; }),
    getJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`, 'application/rdap+json').then(d => (d ? parseIpRdap(d) : {})).catch(() => { errors.push('RDAP unavailable'); return {}; }),
  ]);
  return { ip, ...network, ...rdap, holder: await holderFor(network.asns[0]), error: errors.join('; ') || null };
}

async function describeDomain(host) {
  const dns = type => getJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, 'application/dns-json')
    .then(d => parseDoh(d, type));
  const domain = registeredDomain(host);
  if (!domain) throw new Error('Enter a registered domain, not a public suffix');
  const [a, aaaa, rdap] = await Promise.all([
    dns('A'), dns('AAAA'),
    getJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, 'application/rdap+json').then(d => (d ? parseDomainRdap(d) : null)).catch(() => undefined),
  ]);
  return { host, domain, rcode: a.rcode, ips: [...a.values, ...aaaa.values], rdap };
}

function renderLookup() {
  const { target, domain, addresses } = current;
  const list = $('#contacts');
  list.replaceChildren();
  for (const contact of current.contacts) {
    const item = el('li');
    item.append(el('strong', `${contact.role}: `), `${contact.name} — `);
    const href = contact.contact;
    item.append(el('a', href.replace(/^mailto:/, ''), { href, rel: 'noreferrer noopener' }));
    item.append(el('p', contact.why, { class: 'muted' }));
    list.append(item);
  }
  if (!current.contacts.length) list.append(el('li', 'No abuse contact was found in the public records. Try the hosting company’s website, or the registrar’s abuse page.'));

  const facts = $('#domain-facts');
  facts.replaceChildren();
  if (target.kind === 'ip') {
    fact(facts, 'Domain', 'An IP address was entered, so there is no domain record.');
  } else {
    fact(facts, 'Host', domain.host);
    fact(facts, 'Registered domain', domain.domain);
    fact(facts, 'DNS', domain.rcode);
    if (domain.rdap) {
      const age = ageInDays(domain.rdap.registered);
      fact(facts, 'Registrar', domain.rdap.registrar);
      fact(facts, 'Registrar abuse contact', domain.rdap.abuse);
      fact(facts, 'Registered', domain.rdap.registered ? `${domain.rdap.registered.slice(0, 10)}${age != null ? ` (${age} days ago${age < 30 ? ' — very new' : ''})` : ''}` : null);
      fact(facts, 'Expires', domain.rdap.expires?.slice(0, 10));
      fact(facts, 'Registry status', domain.rdap.statuses);
      fact(facts, 'Nameservers', domain.rdap.nameservers);
    } else if (domain.rdap === null) {
      fact(facts, 'Registration', 'No registration record found. The domain may be deleted, or this registry has no RDAP service.');
    } else {
      fact(facts, 'Registration', 'The registration lookup failed. Try again.');
    }
  }
  const body = $('#addresses tbody');
  body.replaceChildren();
  for (const address of addresses) {
    const provider = address.asns.map(asn => providerFor(asn, config.providers)).find(Boolean);
    const network = `${address.asns.length ? `AS${address.asns.join(', AS')} ` : ''}${address.holder ?? address.organization ?? address.network ?? ''}${provider ? ` · ${provider.kind === 'cdn' ? 'CDN' : 'cloud'}` : ''}`;
    const tr = el('tr');
    tr.append(el('td', address.ip), el('td', network.trim() || '—'), el('td', address.prefix ?? '—'), el('td', address.error || address.abuse || '—'));
    body.append(tr);
  }
  $('#addresses').hidden = !addresses.length;
  $('#lookup-result').hidden = false;

  const recipient = $('#draft-recipient');
  recipient.replaceChildren();
  current.contacts.forEach((contact, i) => recipient.append(el('option', `${contact.role}: ${contact.name}`, { value: String(i) })));
  recipient.append(el('option', 'Someone else', { value: '' }));
  $('#draft-section').hidden = false;
  renderDraft();
}

function renderDraft() {
  if (!current) return;
  const recipient = selectRecipient(current.contacts, $('#draft-recipient').value);
  const draft = draftReport({
    target: current.target, kind: $('#draft-kind').value, brand: $('#draft-brand').value, evidence: $('#draft-evidence').value,
    reporter: $('#draft-reporter').value, observedAt: current.observedAt, domain: current.domain?.rdap ?? null,
    addresses: current.addresses, recipient,
  });
  $('#draft-subject').value = draft.subject;
  $('#draft-body').value = draft.body;
  const link = mailtoLink(recipient, draft);
  $('#draft-mail').hidden = !link;
  if (link) $('#draft-mail').setAttribute('href', link);
  else $('#draft-mail').removeAttribute('href');
}

async function lookup(event) {
  event.preventDefault();
  const run = ++lookupRun;
  if (!config) return;
  const status = $('#lookup-status');
  let target;
  try {
    target = parseInput($('#lookup-input').value);
  } catch (error) {
    status.textContent = error.message;
    return;
  }
  status.textContent = `Looking up ${target.value}…`;
  $('#lookup-result').hidden = true;
  $('#draft-section').hidden = true;
  try {
    const observedAt = utc(new Date());
    let domain = null;
    let ips = [];
    if (target.kind === 'domain') {
      domain = await describeDomain(target.value);
      ips = domain.ips.filter(isPublicIP).slice(0, config.max_addresses_per_target);
    } else {
      ips = [target.value];
    }
    const addresses = await Promise.all(ips.map(describeAddress));
    if (run !== lookupRun) return;
    current = { target, domain, addresses, observedAt,
      contacts: contacts({ domain: domain?.rdap, addresses, providers: config.providers }) };
    renderLookup();
    const note = target.kind === 'domain' && domain.rcode === 'NXDOMAIN' ? ' The domain does not resolve right now.' : '';
    const partial = addresses.some(a => a.error) ? ' Some network/contact lookups were unavailable or skipped; see the table.' : '';
    status.textContent = `Looked up ${target.value} at ${observedAt}.${note}${partial}`;
  } catch {
    if (run !== lookupRun) return;
    status.textContent = 'The lookup failed. Your network or a browser extension may be blocking it; try again.';
  }
}

async function bulk() {
  if (!config) return;
  const run = ++bulkRun;
  const status = $('#bulk-status');
  const { ips, truncated } = extractIPs($('#bulk-input').value, config.bulk_limit);
  if (!ips.length) { status.textContent = 'No IP addresses found in that text.'; return; }
  $('#bulk-run').disabled = true;
  $('#bulk-stop').hidden = false;
  $('#bulk-csv').hidden = true;
  const rows = [];
  let next = 0;
  const worker = async () => {
    while (next < ips.length && run === bulkRun) {
      const ip = ips[next++];
      if (!isPublicIP(ip)) { rows.push({ ip, asns: [], error: 'private or reserved address' }); continue; }
      try { rows.push(await describeAddress(ip)); } catch { rows.push({ ip, asns: [], error: 'lookup failed' }); }
      if (run === bulkRun) status.textContent = `Looked up ${rows.length} of ${ips.length}…`;
    }
  };
  await Promise.all(Array.from({ length: config.bulk_concurrency }, worker));
  $('#bulk-run').disabled = false;
  $('#bulk-stop').hidden = true;
  const groups = groupByAsn(rows.filter(r => r.asns.length));
  const body = $('#bulk tbody');
  body.replaceChildren();
  for (const group of groups) {
    const tr = el('tr');
    const ipsCell = el('td');
    ipsCell.append(el('strong', `${group.ips.length} `), el('span', group.ips.join(', '), { class: 'mono' }));
    tr.append(el('td', `${group.asn}${group.holder ? ` ${group.holder}` : ''}`), ipsCell, el('td', group.abuse ?? '—'));
    body.append(tr);
  }
  $('#bulk').hidden = !groups.length;
  const skipped = rows.filter(r => !r.asns.length).length;
  status.textContent = `${rows.length} ${rows.length === 1 ? 'address' : 'addresses'} in ${groups.length} ${groups.length === 1 ? 'network' : 'networks'}${skipped ? `; ${skipped} skipped, unavailable or without a network match` : ''}${truncated ? `. Only the first ${config.bulk_limit} addresses were looked up` : ''}${run !== bulkRun ? ' (stopped early)' : ''}.`;
  if (csvUrl) URL.revokeObjectURL(csvUrl);
  csvUrl = URL.createObjectURL(new Blob([toCsv(rows)], { type: 'text/csv' }));
  $('#bulk-csv').setAttribute('href', csvUrl);
  $('#bulk-csv').hidden = false;
}

for (const [value, label] of Object.entries(ABUSE_TYPES)) $('#draft-kind').append(el('option', label[0].toUpperCase() + label.slice(1), { value }));
$('#lookup-form').addEventListener('submit', lookup);
for (const id of ['#draft-recipient', '#draft-kind']) $(id).addEventListener('change', renderDraft);
for (const id of ['#draft-brand', '#draft-reporter', '#draft-evidence']) $(id).addEventListener('input', renderDraft);
$('#bulk-run').addEventListener('click', bulk);
$('#bulk-stop').addEventListener('click', () => { bulkRun += 1; });
$('#draft-copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(`Subject: ${$('#draft-subject').value}\n\n${$('#draft-body').value}`);
    $('#draft-status').textContent = 'Copied.';
  } catch {
    $('#draft-body').select();
    $('#draft-status').textContent = 'Copy was unavailable; the message is selected so you can copy it.';
  }
});

try {
  const response = await fetch('./config.json');
  if (!response.ok) throw new Error(String(response.status));
  config = await response.json();
  $('#lookup-form button').disabled = false;
  $('#bulk-run').disabled = false;
} catch {
  $('#lookup-status').textContent = 'The tool settings could not be loaded. Reload the page.';
  $('#lookup-form button').disabled = true;
  $('#bulk-run').disabled = true;
}
