const $ = (id) => document.getElementById(id);
const value = (item) => item === null || item === undefined || item === '' ? '—' : String(item);
const time = (ms) => ms ? new Date(ms).toLocaleString() : '—';

function cell(row, content, className) {
  const td = document.createElement('td');
  td.textContent = value(content);
  if (className) td.className = className;
  row.append(td);
}

function badge(state) {
  const span = document.createElement('span');
  span.className = `badge ${String(state || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '')}`;
  span.textContent = value(state);
  return span;
}

function stateCell(row, state) {
  const td = document.createElement('td');
  td.append(badge(state));
  row.append(td);
}

function fillTable(tableId, items, columns) {
  const tbody = $(tableId).querySelector('tbody');
  const rows = items.map((item) => {
    const row = document.createElement('tr');
    columns.forEach((column) => column(row, item));
    return row;
  });
  if (!rows.length) {
    const row = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = columns.length;
    td.className = 'empty';
    td.textContent = 'Nothing observed yet.';
    row.append(td);
    rows.push(row);
  }
  tbody.replaceChildren(...rows);
}

function summaryCard(label, number) {
  const card = document.createElement('div');
  card.className = 'summary-card';
  const strong = document.createElement('strong');
  strong.textContent = value(number);
  const span = document.createElement('span');
  span.textContent = label;
  card.append(strong, span);
  return card;
}

function render(snapshot) {
  const peers = snapshot.local_peers || [];
  const localMacs = snapshot.local_proxy_macs || [];
  const routes = snapshot.upstream_routes || [];
  const macs = snapshot.managed_macs || [];
  const circuits = snapshot.circuits || [];
  const upstream = snapshot.concentrator;

  $('summary').replaceChildren(
    summaryCard('Local peers', peers.length),
    summaryCard('Local proxy MACs', localMacs.length),
    summaryCard('Upstream routes', routes.length),
    summaryCard('Managed MACs', macs.length),
    summaryCard('Circuits', circuits.length),
  );
  $('peer-count').textContent = peers.length;
  $('local-mac-count').textContent = localMacs.length;
  $('route-count').textContent = routes.length;
  $('mac-count').textContent = macs.length;
  $('circuit-count').textContent = circuits.length;
  $('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;

  const concentrator = $('concentrator');
  if (!upstream) {
    concentrator.textContent = 'Standalone mode: no concentrator configured.';
  } else {
    const wrapper = document.createElement('div');
    wrapper.className = 'upstream';
    wrapper.append(badge(upstream.state));
    for (const [label, entry] of [
      ['Server', upstream.authority],
      ['Router ID', upstream.router_id],
      ['Assigned NETID', upstream.allowed_netid],
      ['Connection epoch', upstream.connection_epoch],
      ['Changed', time(upstream.last_change_ms)],
      ['Last error', upstream.last_error],
    ]) {
      const pair = document.createElement('div');
      const key = document.createElement('span');
      key.textContent = label;
      const val = document.createElement('strong');
      val.textContent = value(entry);
      pair.append(key, val);
      wrapper.append(pair);
    }
    concentrator.replaceChildren(wrapper);
  }

  fillTable('peers', peers, [
    (r, p) => stateCell(r, p.state),
    (r, p) => cell(r, [p.cp, ...(p.lus || [])].filter(Boolean).join(' · ')),
    (r, p) => cell(r, p.transport),
    (r, p) => cell(r, p.locator, 'mono'),
    (r, p) => cell(r, time(p.last_seen_ms)),
    (r, p) => cell(r, p.last_error || p.key),
  ]);
  fillTable('local-macs', localMacs, [
    (r, p) => cell(r, p.attachment_id),
    (r, p) => cell(r, p.mac, 'mono'),
  ]);
  fillTable('routes', routes, [
    (r, p) => cell(r, p.resource),
    (r, p) => cell(r, p.hosting_cp),
    (r, p) => cell(r, p.origin_router_id, 'mono'),
    (r, p) => cell(r, p.generation),
    (r, p) => cell(r, time(p.last_seen_ms)),
  ]);
  fillTable('macs', macs, [
    (r, p) => cell(r, p.cp),
    (r, p) => cell(r, p.mac, 'mono'),
    (r, p) => cell(r, time(p.last_seen_ms)),
  ]);
  fillTable('circuits', circuits, [
    (r, p) => stateCell(r, p.state),
    (r, p) => cell(r, p.ingress),
    (r, p) => cell(r, p.egress),
    (r, p) => cell(r, `${p.bytes_in || 0} in · ${p.bytes_out || 0} out`),
    (r, p) => cell(r, time(p.last_change_ms)),
    (r, p) => cell(r, p.id, 'mono'),
  ]);
}

async function refresh() {
  try {
    const response = await fetch('/api/status', {cache: 'no-store'});
    if (response.status === 401) {
      location.replace('/login');
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    $('updated').textContent = `Status unavailable: ${error.message}`;
  }
}

fetch('/api/auth').then((response) => response.json()).then((auth) => {
  $('logout').hidden = !auth.required;
});
refresh();
setInterval(refresh, 2000);
