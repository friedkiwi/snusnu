const $ = (id) => document.getElementById(id);
const value = (item) => item === null || item === undefined || item === '' ? '—' : String(item);
const time = (ms) => ms ? new Date(ms).toLocaleString() : '—';
const pages = {
  '/': ['overview', 'Overview', 'Current status and a summary of the router.'],
  '/concentrator': ['concentrator', 'Concentrator', 'Connection details and received route count.'],
  '/routes': ['routes', 'Upstream routes', 'Routes received from the concentrator.'],
  '/concentrator/routes': ['routes', 'Upstream routes', 'Routes received from the concentrator.'],
  '/peers': ['peers', 'Local peers', 'Peers observed on local attachments.'],
  '/addresses': ['addresses', 'Addresses', 'Proxy and managed MAC addresses.'],
  '/circuits': ['circuits', 'Circuits', 'Current routed circuits.'],
};
const [page, title, description] = pages[location.pathname] || pages['/'];
$('page-title').textContent = title;
$('page-description').textContent = description;
$(`${page}-page`).hidden = false;
document.querySelectorAll('.sidebar a').forEach((link) => {
  if (link.dataset.page === page) {
    link.classList.add('active');
    link.setAttribute('aria-current', 'page');
  }
});

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

function summaryCard(label, number, href) {
  const card = document.createElement('a');
  card.className = 'summary-card';
  card.href = href;
  const strong = document.createElement('strong');
  strong.textContent = value(number);
  const span = document.createElement('span');
  span.textContent = label;
  card.append(strong, span);
  return card;
}

function concentratorDetails(target, upstream) {
  if (!upstream) {
    target.textContent = 'Standalone mode: no concentrator configured.';
    return;
  }
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
  target.replaceChildren(wrapper);
}

function concentratorSummary(target, upstream) {
  if (!upstream) {
    target.textContent = 'Standalone mode: no concentrator configured.';
    return;
  }
  const wrapper = document.createElement('div');
  wrapper.className = 'upstream';
  wrapper.append(badge(upstream.state));
  const authority = document.createElement('strong');
  authority.textContent = value(upstream.authority);
  wrapper.append(authority);
  target.replaceChildren(wrapper);
}

function renderView(snapshot) {
  const peers = snapshot.local_peers || [];
  const localMacs = snapshot.local_proxy_macs || [];
  const macs = snapshot.managed_macs || [];
  const circuits = snapshot.circuits || [];
  const routeCount = snapshot.upstream_route_count || 0;

  if (page === 'overview') {
    $('summary').replaceChildren(
      summaryCard('Local peers', peers.length, '/peers'),
      summaryCard('Local proxy MACs', localMacs.length, '/addresses'),
      summaryCard('Upstream routes', routeCount, '/routes'),
      summaryCard('Managed MACs', macs.length, '/addresses'),
      summaryCard('Circuits', circuits.length, '/circuits'),
    );
    concentratorSummary($('concentrator-summary'), snapshot.concentrator);
  } else if (page === 'concentrator') {
    concentratorDetails($('concentrator'), snapshot.concentrator);
    $('concentrator-route-count').textContent = `${routeCount} routes received`;
  } else if (page === 'peers') {
    $('peer-count').textContent = peers.length;
    fillTable('peers', peers, [
      (r, p) => stateCell(r, p.state),
      (r, p) => cell(r, [p.cp, ...(p.lus || [])].filter(Boolean).join(' · ')),
      (r, p) => cell(r, p.transport),
      (r, p) => cell(r, p.locator, 'mono'),
      (r, p) => cell(r, time(p.last_seen_ms)),
      (r, p) => cell(r, p.last_error || p.key),
    ]);
  } else if (page === 'addresses') {
    $('local-mac-count').textContent = localMacs.length;
    $('mac-count').textContent = macs.length;
    fillTable('local-macs', localMacs, [
      (r, p) => cell(r, p.attachment_id),
      (r, p) => cell(r, p.mac, 'mono'),
    ]);
    fillTable('macs', macs, [
      (r, p) => cell(r, p.cp),
      (r, p) => cell(r, p.mac, 'mono'),
      (r, p) => cell(r, time(p.last_seen_ms)),
    ]);
  } else if (page === 'circuits') {
    $('circuit-count').textContent = circuits.length;
    fillTable('circuits', circuits, [
      (r, p) => stateCell(r, p.state),
      (r, p) => cell(r, p.ingress),
      (r, p) => cell(r, p.egress),
      (r, p) => cell(r, `${p.bytes_in || 0} in · ${p.bytes_out || 0} out`),
      (r, p) => cell(r, time(p.last_change_ms)),
      (r, p) => cell(r, p.id, 'mono'),
    ]);
  }
  $('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

const initialParams = new URLSearchParams(location.search);
const routesState = {
  q: initialParams.get('q') || '',
  page: Math.max(1, Number.parseInt(initialParams.get('page') || '1', 10) || 1),
  perPage: [25, 50, 100].includes(Number(initialParams.get('per_page'))) ? Number(initialParams.get('per_page')) : 25,
  request: 0,
};

function rememberRouteState() {
  const params = new URLSearchParams();
  if (routesState.q) params.set('q', routesState.q);
  if (routesState.page > 1) params.set('page', String(routesState.page));
  if (routesState.perPage !== 25) params.set('per_page', String(routesState.perPage));
  const query = params.toString();
  history.replaceState(null, '', `${location.pathname}${query ? `?${query}` : ''}`);
}

async function refreshRoutes() {
  const request = ++routesState.request;
  const params = new URLSearchParams({q: routesState.q, page: String(routesState.page), per_page: String(routesState.perPage)});
  try {
    const response = await fetch(`/api/routes?${params}`, {cache: 'no-store'});
    if (response.status === 401) {
      location.replace('/login');
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (request !== routesState.request) return;
    const total = data.total || 0;
    const maxPage = Math.max(1, Math.ceil(total / routesState.perPage));
    if (routesState.page > maxPage) {
      routesState.page = maxPage;
      rememberRouteState();
      refreshRoutes();
      return;
    }
    routesState.page = data.page || 1;
    routesState.perPage = data.per_page || routesState.perPage;
    rememberRouteState();
    $('route-count').textContent = total;
    fillTable('routes', data.items || [], [
      (r, p) => cell(r, p.resource),
      (r, p) => cell(r, p.hosting_cp),
      (r, p) => cell(r, p.origin_router_id, 'mono'),
      (r, p) => cell(r, p.generation),
      (r, p) => cell(r, time(p.last_seen_ms)),
    ]);
    const first = total ? (routesState.page - 1) * routesState.perPage + 1 : 0;
    const last = Math.min(routesState.page * routesState.perPage, total);
    $('route-range').textContent = `${first}–${last} of ${total}`;
    $('route-prev').disabled = routesState.page <= 1;
    $('route-next').disabled = last >= total;
    $('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    if (request === routesState.request) $('updated').textContent = `Routes unavailable: ${error.message}`;
  }
}

async function refreshView() {
  try {
    const response = await fetch('/api/view', {cache: 'no-store'});
    if (response.status === 401) {
      location.replace('/login');
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderView(await response.json());
  } catch (error) {
    $('updated').textContent = `Status unavailable: ${error.message}`;
  }
}

if (page === 'routes') {
  $('route-search').value = routesState.q;
  $('route-page-size').value = String(routesState.perPage);
  let searchTimer;
  $('route-search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      routesState.q = $('route-search').value.trim();
      routesState.page = 1;
      rememberRouteState();
      refreshRoutes();
    }, 250);
  });
  $('route-page-size').addEventListener('change', () => {
    routesState.perPage = Number($('route-page-size').value);
    routesState.page = 1;
    rememberRouteState();
    refreshRoutes();
  });
  $('route-prev').addEventListener('click', () => {
    if (routesState.page <= 1) return;
    routesState.page--;
    rememberRouteState();
    refreshRoutes();
  });
  $('route-next').addEventListener('click', () => {
    routesState.page++;
    rememberRouteState();
    refreshRoutes();
  });
  refreshRoutes();
  setInterval(refreshRoutes, 2000);
} else {
  refreshView();
  setInterval(refreshView, 2000);
}

fetch('/api/auth').then((response) => response.json()).then((auth) => {
  $('logout').hidden = !auth.required;
});
