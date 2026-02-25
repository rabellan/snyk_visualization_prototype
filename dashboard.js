'use strict';

/* ===================================================================
   Snyk Vulnerability Dashboard — JavaScript
   =================================================================== */

// ─── Constants ───────────────────────────────────────────────────────
const SEVERITY_COLORS = {
  critical: '#AB1A1A',
  high:     '#CE5019',
  medium:   '#D68000',
  low:      '#88879E',
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const SCAN_COLORS = { sca: '#3B82F6', sast: '#8B5CF6', iac: '#10B981' };

const EXPLOIT_COLORS = {
  'no-known-exploit': '#88879E',
  'proof-of-concept': '#D68000',
  'mature':           '#AB1A1A',
};

// Shared Plotly layout defaults
const BASE_LAYOUT = {
  paper_bgcolor: 'transparent',
  plot_bgcolor:  'transparent',
  font: {
    family: "-apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif",
    size: 11,
    color: '#475569',
  },
  xaxis: { gridcolor: '#F1F5F9', zerolinecolor: '#E2E8F0', linecolor: '#E2E8F0' },
  yaxis: { gridcolor: '#F1F5F9', zerolinecolor: '#E2E8F0', linecolor: '#E2E8F0' },
  legend: { bgcolor: 'transparent', bordercolor: 'transparent' },
  hoverlabel: { bgcolor: '#1E293B', bordercolor: '#1E293B', font: { color: '#F8FAFC', size: 12 } },
};

const PLOTLY_CONFIG = {
  responsive:              true,
  displayModeBar:          true,
  modeBarButtonsToRemove: ['select2d', 'lasso2d', 'autoScale2d', 'toggleSpikelines'],
  displaylogo:             false,
  toImageButtonOptions:    { format: 'png', scale: 2 },
};

// ─── State ───────────────────────────────────────────────────────────
let allData      = [];
let filteredData = [];
let activeOrgs       = new Set(['__all__']);
let activeScanTypes  = new Set(['__all__']);

// ─── Utilities ───────────────────────────────────────────────────────
function countBy(arr, key) {
  return arr.reduce((acc, item) => {
    const k = item[key] || '';
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});
}

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function layout(overrides) {
  return Object.assign({}, BASE_LAYOUT,
    { xaxis: { ...BASE_LAYOUT.xaxis }, yaxis: { ...BASE_LAYOUT.yaxis } },
    overrides,
  );
}

function renderEmpty(id, msg = 'No data available for the current selection') {
  const el = document.getElementById(id);
  if (!el) return;
  try { Plotly.purge(el); } catch (_) { /* ignore */ }
  el.innerHTML = `<div class="chart-empty">${msg}</div>`;
}

// ─── Data Loading ────────────────────────────────────────────────────
function parseRow(d) {
  return {
    ...d,
    cvss_score:      parseFloat(d.cvss_score)      || 0,
    priority_score:  parseInt(d.priority_score, 10) || 0,
    resolution_days: d.resolution_days ? parseFloat(d.resolution_days) : null,
    is_fixable:      d.is_fixable === 'True',
    discovered_date: new Date(d.discovered_date),
    introduced_date: new Date(d.introduced_date),
    resolved_date:   d.resolved_date ? new Date(d.resolved_date) : null,
  };
}

function parseCsv(csvText) {
  const result = Papa.parse(csvText, { header: true, skipEmptyLines: true });
  return result.data.filter(d => d.issue_id && d.issue_id.trim()).map(parseRow);
}

async function loadDataFetch() {
  const res = await fetch('snyk_vulnerability_dataset.csv');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  return parseCsv(text);
}

// ─── Filters ─────────────────────────────────────────────────────────
function buildFilters(data) {
  const orgs      = [...new Set(data.map(d => d.org_name))].sort();
  const scanTypes = [...new Set(data.map(d => d.scan_type))].sort();

  buildChipGroup('filter-org',  orgs,                 'org');
  buildChipGroup('filter-scan', scanTypes.map(s => s.toUpperCase()), 'scan', scanTypes);
}

function buildChipGroup(containerId, labels, type, values) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  const vals = values || labels.map(l => l.toLowerCase());

  // "All" chip
  container.appendChild(createChip('All', '__all__', type, true));

  labels.forEach((label, i) => {
    container.appendChild(createChip(label, vals[i], type, false));
  });
}

function createChip(label, value, type, active) {
  const btn = document.createElement('button');
  btn.className        = 'chip' + (active ? ' active' : '');
  btn.textContent      = label;
  btn.dataset.value    = value;
  btn.dataset.type     = type;
  btn.addEventListener('click', () => handleChipClick(btn, type));
  return btn;
}

function handleChipClick(chip, type) {
  const value     = chip.dataset.value;
  const activeSet = type === 'org' ? activeOrgs : activeScanTypes;
  const container = document.getElementById(type === 'org' ? 'filter-org' : 'filter-scan');
  const chips     = container ? container.querySelectorAll('.chip') : [];

  if (value === '__all__') {
    activeSet.clear();
    activeSet.add('__all__');
    chips.forEach(c => c.classList.toggle('active', c.dataset.value === '__all__'));
  } else {
    activeSet.delete('__all__');
    if (activeSet.has(value)) {
      activeSet.delete(value);
      if (activeSet.size === 0) activeSet.add('__all__');
    } else {
      activeSet.add(value);
    }
    chips.forEach(c => {
      if (c.dataset.value === '__all__') {
        c.classList.toggle('active', activeSet.has('__all__'));
      } else {
        c.classList.toggle('active', activeSet.has(c.dataset.value));
      }
    });
  }

  applyFilters();
}

function applyFilters() {
  filteredData = allData.filter(d => {
    const orgOk  = activeOrgs.has('__all__')      || activeOrgs.has(d.org_name);
    const scanOk = activeScanTypes.has('__all__') || activeScanTypes.has(d.scan_type);
    return orgOk && scanOk;
  });
  renderAll();
}

// ─── KPIs ─────────────────────────────────────────────────────────────
function updateKPIs(data) {
  const open  = data.filter(d => d.status === 'open');
  const fixed = data.filter(d => d.status === 'fixed' && d.resolution_days !== null);

  const fmt = n => n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);

  setText('kpi-total',    fmt(data.length));
  setText('kpi-critical', open.filter(d => d.severity === 'critical').length);
  setText('kpi-high',     open.filter(d => d.severity === 'high').length);
  setText('kpi-fixed',    fmt(fixed.length));

  const avgMttr = fixed.length ? mean(fixed.map(d => d.resolution_days)) : null;
  setText('kpi-mttr', avgMttr !== null ? avgMttr.toFixed(1) : '—');
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ─── Header summary ───────────────────────────────────────────────────
function updateHeaderSummary(data) {
  const el = document.getElementById('data-summary');
  if (!el) return;

  const nOrgs    = new Set(data.map(d => d.org_name)).size;
  const nProj    = new Set(data.map(d => d.project_name)).size;
  const dates    = data.map(d => d.discovered_date.getTime()).filter(Boolean);
  const dateMin  = new Date(Math.min(...dates));
  const dateMax  = new Date(Math.max(...dates));
  const fmtMonth = d => d.toISOString().slice(0, 7);

  el.innerHTML = [
    `<span class="badge">${data.length} issues</span>`,
    `<span class="badge">${nOrgs} orgs</span>`,
    `<span class="badge">${nProj} projects</span>`,
    `<span class="badge">${fmtMonth(dateMin)} – ${fmtMonth(dateMax)}</span>`,
  ].join('');
}

/* ===================================================================
   Chart Renderers
   =================================================================== */

// 1 ─── Heatmap: Open issues by Org × Severity ────────────────────────
function renderHeatmap(data) {
  const open = data.filter(d => d.status === 'open');
  const orgs = [...new Set(data.map(d => d.org_name))].sort();

  if (!open.length) { renderEmpty('chart-heatmap'); return; }

  const z = orgs.map(org =>
    SEVERITY_ORDER.map(sev =>
      open.filter(d => d.org_name === org && d.severity === sev).length
    )
  );

  const trace = {
    type: 'heatmap',
    z,
    x: SEVERITY_ORDER,
    y: orgs,
    colorscale: [
      [0,    '#FEF3C7'],
      [0.25, '#FCA5A5'],
      [0.5,  '#EF4444'],
      [0.75, '#B91C1C'],
      [1,    '#7F1D1D'],
    ],
    text:         z.map(row => row.map(v => v > 0 ? String(v) : '')),
    texttemplate: '%{text}',
    textfont:     { size: 13, color: 'white' },
    showscale:    true,
    colorbar:     { title: { text: 'Count', side: 'right' }, tickfont: { size: 10 }, len: 0.85 },
    hovertemplate: '<b>%{y}</b><br>%{x}: <b>%{z}</b><extra></extra>',
  };

  Plotly.react('chart-heatmap', [trace], layout({
    margin: { t: 10, r: 80, b: 50, l: 180 },
    xaxis: { ...BASE_LAYOUT.xaxis, side: 'bottom' },
    yaxis: { ...BASE_LAYOUT.yaxis, automargin: true },
  }), PLOTLY_CONFIG);
}

// 2 ─── Org Totals: Horizontal bar ────────────────────────────────────
function renderOrgTotals(data) {
  const open = data.filter(d => d.status === 'open');
  if (!open.length) { renderEmpty('chart-org-totals'); return; }

  const counts = countBy(open, 'org_name');
  const sorted = Object.entries(counts).sort((a, b) => a[1] - b[1]);
  const vals   = sorted.map(d => d[1]);
  const med    = vals.length ? vals[Math.floor(vals.length / 2)] : 0;

  const trace = {
    type:        'bar',
    x:           vals,
    y:           sorted.map(d => d[0]),
    orientation: 'h',
    marker: { color: vals.map(v => v > med ? '#CE5019' : '#D68000') },
    text:        vals.map(String),
    textposition: 'outside',
    cliponaxis:   false,
    hovertemplate: '<b>%{y}</b><br>Open: <b>%{x}</b><extra></extra>',
  };

  Plotly.react('chart-org-totals', [trace], layout({
    margin: { t: 10, r: 50, b: 40, l: 170 },
    xaxis: { ...BASE_LAYOUT.xaxis, title: { text: 'Count' } },
    yaxis: { ...BASE_LAYOUT.yaxis, automargin: true },
    bargap: 0.3,
  }), PLOTLY_CONFIG);
}

// 3 ─── Severity stacked bar by org ───────────────────────────────────
function renderSeverityBar(data) {
  const orgs = [...new Set(data.map(d => d.org_name))].sort();

  const traces = SEVERITY_ORDER.map(sev => ({
    type:  'bar',
    name:  sev,
    x:     orgs,
    y:     orgs.map(org => data.filter(d => d.org_name === org && d.severity === sev).length),
    marker: { color: SEVERITY_COLORS[sev] },
    hovertemplate: `<b>%{x}</b><br>${sev}: <b>%{y}</b><extra></extra>`,
  }));

  Plotly.react('chart-severity-bar', traces, layout({
    barmode: 'stack',
    margin:  { t: 10, r: 10, b: 90, l: 50 },
    xaxis:   { ...BASE_LAYOUT.xaxis, tickangle: -30 },
    yaxis:   { ...BASE_LAYOUT.yaxis, title: { text: 'Issue Count' } },
    legend:  { ...BASE_LAYOUT.legend, x: 1, xanchor: 'right', y: 1 },
  }), PLOTLY_CONFIG);
}

// 4 ─── Severity pie ───────────────────────────────────────────────────
function renderSeverityPie(data) {
  const counts = SEVERITY_ORDER.map(sev => data.filter(d => d.severity === sev).length);

  const trace = {
    type:     'pie',
    values:   counts,
    labels:   SEVERITY_ORDER,
    marker:   { colors: SEVERITY_ORDER.map(s => SEVERITY_COLORS[s]) },
    textinfo: 'label+percent',
    textfont: { size: 12 },
    hole:     0.38,
    hovertemplate: '<b>%{label}</b><br>%{value} issues (%{percent})<extra></extra>',
    sort:     false,
  };

  Plotly.react('chart-severity-pie', [trace], layout({
    margin:     { t: 20, r: 20, b: 20, l: 20 },
    showlegend: true,
    legend:     { orientation: 'h', y: -0.12, x: 0.5, xanchor: 'center' },
  }), PLOTLY_CONFIG);
}

// 5 ─── Monthly Discovery Trend ────────────────────────────────────────
function renderTrend(data) {
  if (!data.length) { renderEmpty('chart-trend'); return; }

  data.forEach(d => {
    const dt = d.discovered_date;
    d._mkey = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
  });

  const months = [...new Set(data.map(d => d._mkey))].sort();

  // Bottom-to-top order so critical ends up visually on top
  const stackOrder = ['low', 'medium', 'high', 'critical'];

  const traces = stackOrder.map(sev => ({
    type:       'scatter',
    mode:       'lines',
    name:       sev,
    x:          months,
    y:          months.map(m => data.filter(d => d._mkey === m && d.severity === sev).length),
    stackgroup: 'one',
    fillcolor:  SEVERITY_COLORS[sev] + 'CC',
    line:       { color: SEVERITY_COLORS[sev], width: 0.5 },
    hovertemplate: `%{x}<br>${sev}: <b>%{y}</b><extra></extra>`,
  }));

  Plotly.react('chart-trend', traces, layout({
    margin: { t: 10, r: 10, b: 55, l: 55 },
    xaxis:  { ...BASE_LAYOUT.xaxis, title: { text: 'Month' }, tickangle: -30, nticks: 14 },
    yaxis:  { ...BASE_LAYOUT.yaxis, title: { text: 'Issues Discovered' } },
    legend: { orientation: 'h', y: 1.1, x: 0.5, xanchor: 'center',
              traceorder: 'reversed' },
  }), PLOTLY_CONFIG);
}

// 6 ─── Scan Type bar ──────────────────────────────────────────────────
function renderScanType(data) {
  const orgs      = [...new Set(data.map(d => d.org_name))].sort();
  const scanTypes = [...new Set(data.map(d => d.scan_type))].sort();

  const traces = scanTypes.map(type => ({
    type:  'bar',
    name:  type.toUpperCase(),
    x:     orgs,
    y:     orgs.map(org => data.filter(d => d.org_name === org && d.scan_type === type).length),
    marker: { color: SCAN_COLORS[type] || '#888' },
    hovertemplate: `<b>%{x}</b><br>${type.toUpperCase()}: <b>%{y}</b><extra></extra>`,
  }));

  Plotly.react('chart-scan-type', traces, layout({
    barmode: 'group',
    margin:  { t: 10, r: 10, b: 90, l: 50 },
    xaxis:   { ...BASE_LAYOUT.xaxis, tickangle: -30 },
    yaxis:   { ...BASE_LAYOUT.yaxis, title: { text: 'Issue Count' } },
  }), PLOTLY_CONFIG);
}

// 7 ─── Scan Severity % mix ────────────────────────────────────────────
function renderScanSeverity(data) {
  const scanTypes = [...new Set(data.map(d => d.scan_type))].sort();
  const totals    = Object.fromEntries(
    scanTypes.map(t => [t, data.filter(d => d.scan_type === t).length])
  );

  const traces = SEVERITY_ORDER.map(sev => ({
    type:        'bar',
    name:        sev,
    y:           scanTypes,
    x:           scanTypes.map(t =>
      totals[t] > 0
        ? (data.filter(d => d.scan_type === t && d.severity === sev).length / totals[t] * 100)
        : 0
    ),
    orientation: 'h',
    marker: { color: SEVERITY_COLORS[sev] },
    hovertemplate: `${sev}: <b>%{x:.1f}%</b><extra></extra>`,
  }));

  Plotly.react('chart-scan-severity', traces, layout({
    barmode: 'stack',
    margin:  { t: 10, r: 10, b: 40, l: 70 },
    xaxis:   { ...BASE_LAYOUT.xaxis, title: { text: 'Percentage' }, range: [0, 100] },
    yaxis:   { ...BASE_LAYOUT.yaxis },
    legend:  { orientation: 'h', y: 1.1, x: 0.5, xanchor: 'center' },
  }), PLOTLY_CONFIG);
}

// 8 ─── Language stacked bar ───────────────────────────────────────────
function renderLanguage(data) {
  const counts = countBy(data, 'language');
  const langs  = Object.entries(counts)
    .sort((a, b) => a[1] - b[1])   // ascending for h-bar (largest on top)
    .map(d => d[0]);

  const traces = SEVERITY_ORDER.map(sev => ({
    type:        'bar',
    name:        sev,
    y:           langs,
    x:           langs.map(lang =>
      data.filter(d => d.language === lang && d.severity === sev).length
    ),
    orientation: 'h',
    marker: { color: SEVERITY_COLORS[sev] },
    hovertemplate: `<b>%{y}</b><br>${sev}: <b>%{x}</b><extra></extra>`,
  }));

  Plotly.react('chart-language', traces, layout({
    barmode: 'stack',
    margin:  { t: 10, r: 10, b: 40, l: 90 },
    xaxis:   { ...BASE_LAYOUT.xaxis, title: { text: 'Issue Count' } },
    yaxis:   { ...BASE_LAYOUT.yaxis, automargin: true },
    legend:  { ...BASE_LAYOUT.legend, x: 1, xanchor: 'right', y: 1 },
  }), PLOTLY_CONFIG);
}

// 9 ─── CVSS box plot by language ─────────────────────────────────────
function renderCVSSBox(data) {
  const vulns = data.filter(d => d.issue_type === 'vuln' && d.cvss_score > 0);

  if (!vulns.length) { renderEmpty('chart-cvss-box', 'No vulnerability data with CVSS scores'); return; }

  const langs = [...new Set(vulns.map(d => d.language))];

  // Sort by median CVSS descending
  const langOrder = langs
    .map(lang => {
      const vals = vulns.filter(d => d.language === lang).map(d => d.cvss_score).sort((a, b) => a - b);
      const med  = vals[Math.floor(vals.length / 2)] || 0;
      return { lang, med };
    })
    .sort((a, b) => a.med - b.med)   // ascending for h-bar
    .map(d => d.lang);

  const traces = langOrder.map(lang => ({
    type:        'box',
    name:        lang,
    x:           vulns.filter(d => d.language === lang).map(d => d.cvss_score),
    orientation: 'h',
    boxmean:     true,
    marker:      { size: 3, color: '#7E3AF2', opacity: 0.5 },
    line:        { color: '#7E3AF2' },
    fillcolor:   '#EDE9FE',
    hovertemplate: `<b>${lang}</b><br>CVSS: %{x:.1f}<extra></extra>`,
  }));

  Plotly.react('chart-cvss-box', traces, layout({
    showlegend: false,
    margin:     { t: 30, r: 20, b: 40, l: 90 },
    xaxis:      { ...BASE_LAYOUT.xaxis, title: { text: 'CVSS Score' }, range: [0, 10.5] },
    yaxis:      { ...BASE_LAYOUT.yaxis, automargin: true },
    shapes: [
      { type: 'line', x0: 7.0, x1: 7.0, y0: 0, y1: 1, yref: 'paper',
        line: { color: 'red', dash: 'dash', width: 1.5 } },
      { type: 'line', x0: 9.0, x1: 9.0, y0: 0, y1: 1, yref: 'paper',
        line: { color: '#7F1D1D', dash: 'dash', width: 1.5 } },
    ],
    annotations: [
      { x: 7.05, y: 1.06, yref: 'paper', text: 'High (7.0)',
        showarrow: false, font: { size: 9, color: 'red' }, xanchor: 'left' },
      { x: 9.05, y: 1.06, yref: 'paper', text: 'Critical (9.0)',
        showarrow: false, font: { size: 9, color: '#7F1D1D' }, xanchor: 'left' },
    ],
  }), PLOTLY_CONFIG);
}

// 10 ─── MTTR bar by org ───────────────────────────────────────────────
function renderMTTRBar(data) {
  const fixed = data.filter(d => d.status === 'fixed' && d.resolution_days !== null);

  if (!fixed.length) { renderEmpty('chart-mttr-bar', 'No fixed issues in current selection'); return; }

  const orgs = [...new Set(data.map(d => d.org_name))].sort();

  const traces = SEVERITY_ORDER.map(sev => ({
    type:  'bar',
    name:  sev,
    x:     orgs,
    y:     orgs.map(org => {
      const vals = fixed.filter(d => d.org_name === org && d.severity === sev)
                        .map(d => d.resolution_days);
      return vals.length ? mean(vals) : null;
    }),
    marker: { color: SEVERITY_COLORS[sev] },
    hovertemplate: `<b>%{x}</b><br>${sev}: <b>%{y:.1f} days</b><extra></extra>`,
  }));

  Plotly.react('chart-mttr-bar', traces, layout({
    barmode: 'group',
    margin:  { t: 30, r: 10, b: 90, l: 60 },
    xaxis:   { ...BASE_LAYOUT.xaxis, tickangle: -30 },
    yaxis:   { ...BASE_LAYOUT.yaxis, title: { text: 'Days' } },
    shapes: [
      { type: 'line', y0: 15, y1: 15, x0: 0, x1: 1, xref: 'paper',
        line: { color: 'red', dash: 'dash', width: 1.5 } },
      { type: 'line', y0: 30, y1: 30, x0: 0, x1: 1, xref: 'paper',
        line: { color: 'orange', dash: 'dash', width: 1.5 } },
    ],
    annotations: [
      { y: 15, x: 1, xref: 'paper', text: 'Critical SLA (15d)',
        showarrow: false, font: { size: 9, color: 'red' }, xanchor: 'right', yanchor: 'bottom' },
      { y: 30, x: 1, xref: 'paper', text: 'High SLA (30d)',
        showarrow: false, font: { size: 9, color: '#D97706' }, xanchor: 'right', yanchor: 'bottom' },
    ],
  }), PLOTLY_CONFIG);
}

// 11 ─── MTTR violin ───────────────────────────────────────────────────
function renderMTTRViolin(data) {
  const fixed = data.filter(d => d.status === 'fixed' && d.resolution_days !== null);

  if (!fixed.length) { renderEmpty('chart-mttr-violin', 'No fixed issues in current selection'); return; }

  const available = SEVERITY_ORDER.filter(sev => fixed.some(d => d.severity === sev));

  const traces = available.map(sev => ({
    type:      'violin',
    name:      sev,
    y:         fixed.filter(d => d.severity === sev).map(d => d.resolution_days),
    fillcolor: SEVERITY_COLORS[sev] + '99',
    line:      { color: SEVERITY_COLORS[sev] },
    box:       { visible: true },
    meanline:  { visible: true },
    points:    'all',
    jitter:    0.25,
    pointpos:  0,
    hovertemplate: `${sev}: <b>%{y:.1f}d</b><extra></extra>`,
  }));

  Plotly.react('chart-mttr-violin', traces, layout({
    showlegend:  false,
    violinmode:  'overlay',
    margin:      { t: 10, r: 10, b: 40, l: 60 },
    xaxis:       { ...BASE_LAYOUT.xaxis },
    yaxis:       { ...BASE_LAYOUT.yaxis, title: { text: 'Days to Fix' } },
  }), PLOTLY_CONFIG);
}

// 12 ─── Fixability by org ─────────────────────────────────────────────
function renderFixability(data) {
  const orgs = [...new Set(data.map(d => d.org_name))].sort();

  const fixPct = orgs.map(org => {
    const orgData = data.filter(d => d.org_name === org);
    return orgData.length
      ? orgData.filter(d => d.is_fixable).length / orgData.length * 100
      : 0;
  });

  const traces = [
    {
      type:        'bar',
      name:        'Fixable',
      y:           orgs,
      x:           fixPct,
      orientation: 'h',
      marker:      { color: '#22C55E' },
      hovertemplate: '<b>%{y}</b><br>Fixable: <b>%{x:.1f}%</b><extra></extra>',
    },
    {
      type:        'bar',
      name:        'Not Fixable',
      y:           orgs,
      x:           fixPct.map(p => 100 - p),
      orientation: 'h',
      marker:      { color: '#EF4444' },
      hovertemplate: '<b>%{y}</b><br>Not Fixable: <b>%{x:.1f}%</b><extra></extra>',
    },
  ];

  Plotly.react('chart-fixability', traces, layout({
    barmode: 'stack',
    margin:  { t: 10, r: 10, b: 40, l: 180 },
    xaxis:   { ...BASE_LAYOUT.xaxis, title: { text: 'Percentage' }, range: [0, 100] },
    yaxis:   { ...BASE_LAYOUT.yaxis, automargin: true },
    legend:  { orientation: 'h', y: 1.1, x: 0.5, xanchor: 'center' },
  }), PLOTLY_CONFIG);
}

// 13 ─── Exploit maturity ──────────────────────────────────────────────
function renderExploit(data) {
  const exploitData = data.filter(
    d => d.issue_type === 'vuln' && d.exploit_maturity && d.exploit_maturity !== ''
  );

  if (!exploitData.length) {
    renderEmpty('chart-exploit', 'No exploit maturity data in current selection');
    return;
  }

  const exploitTypes = [...new Set(exploitData.map(d => d.exploit_maturity))].sort();

  const traces = exploitTypes.map(etype => ({
    type:  'bar',
    name:  etype,
    x:     SEVERITY_ORDER,
    y:     SEVERITY_ORDER.map(sev =>
      exploitData.filter(d => d.severity === sev && d.exploit_maturity === etype).length
    ),
    marker: { color: EXPLOIT_COLORS[etype] || '#888888' },
    hovertemplate: `<b>%{x}</b><br>${etype}: <b>%{y}</b><extra></extra>`,
  }));

  Plotly.react('chart-exploit', traces, layout({
    barmode: 'group',
    margin:  { t: 10, r: 10, b: 40, l: 50 },
    xaxis:   { ...BASE_LAYOUT.xaxis },
    yaxis:   { ...BASE_LAYOUT.yaxis, title: { text: 'Issue Count' } },
    legend:  { orientation: 'h', y: 1.1, x: 0.5, xanchor: 'center' },
  }), PLOTLY_CONFIG);
}

// 14 ─── CWE Top 10 ────────────────────────────────────────────────────
function renderCWE(data) {
  const vulns = data.filter(d => d.issue_type === 'vuln' && d.cwe_id && d.cwe_id !== '');

  if (!vulns.length) {
    renderEmpty('chart-cwe', 'No vulnerability data with CWE IDs in current selection');
    return;
  }

  const cweCounts = countBy(vulns, 'cwe_id');
  const top10ids  = Object.entries(cweCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(d => d[0]);

  // Build human-readable labels
  const labelMap = {};
  vulns.forEach(d => {
    if (top10ids.includes(d.cwe_id) && !labelMap[d.cwe_id] && d.title) {
      labelMap[d.cwe_id] = `${d.cwe_id} — ${d.title}`;
    }
  });

  // Sort ascending by total count (largest at top for h-bar)
  const sorted = top10ids
    .map(id => ({ id, label: labelMap[id] || id, total: cweCounts[id] }))
    .sort((a, b) => a.total - b.total);

  const yLabels = sorted.map(d => d.label);
  const ids     = sorted.map(d => d.id);

  const traces = SEVERITY_ORDER.map(sev => ({
    type:        'bar',
    name:        sev,
    y:           yLabels,
    x:           ids.map(id =>
      vulns.filter(d => d.cwe_id === id && d.severity === sev).length
    ),
    orientation: 'h',
    marker: { color: SEVERITY_COLORS[sev] },
    hovertemplate: `<b>%{y}</b><br>${sev}: <b>%{x}</b><extra></extra>`,
  }));

  Plotly.react('chart-cwe', traces, layout({
    barmode: 'stack',
    margin:  { t: 10, r: 10, b: 40, l: 280 },
    xaxis:   { ...BASE_LAYOUT.xaxis, title: { text: 'Issue Count' } },
    yaxis:   { ...BASE_LAYOUT.yaxis, automargin: true, tickfont: { size: 10 } },
    legend:  { ...BASE_LAYOUT.legend, x: 1, xanchor: 'right', y: 1 },
  }), PLOTLY_CONFIG);
}

// 15 ─── Project Risk Scatter ──────────────────────────────────────────
function renderScatter(data) {
  const open = data.filter(d => d.status === 'open');

  if (!open.length) { renderEmpty('chart-scatter'); return; }

  const projectNames = [...new Set(open.map(d => d.project_name))];

  const stats = projectNames.map(proj => {
    const rows    = open.filter(d => d.project_name === proj);
    const org     = rows[0]?.org_name || '';
    return {
      proj,
      org,
      totalOpen:     rows.length,
      avgCvss:       mean(rows.map(d => d.cvss_score)),
      criticalCount: rows.filter(d => d.severity === 'critical').length,
      highCount:     rows.filter(d => d.severity === 'high').length,
    };
  }).filter(d => d.totalOpen > 0);

  if (!stats.length) { renderEmpty('chart-scatter'); return; }

  const trace = {
    type:     'scatter',
    mode:     'markers+text',
    x:        stats.map(d => d.totalOpen),
    y:        stats.map(d => d.avgCvss),
    text:     stats.map(d => d.proj),
    textposition: 'top center',
    textfont: { size: 9, color: '#475569' },
    marker: {
      size:      stats.map(d => Math.max(10, Math.sqrt(d.criticalCount + 1) * 14 + 6)),
      color:     stats.map(d => d.highCount),
      colorscale: 'YlOrRd',
      showscale:  true,
      colorbar:   {
        title: { text: 'High<br>Issues', side: 'right' },
        len: 0.65,
        tickfont: { size: 10 },
      },
      line:      { color: '#64748B', width: 1 },
      opacity:   0.85,
      sizemode:  'diameter',
    },
    customdata: stats.map(d => [d.org, d.criticalCount, d.highCount, d.totalOpen]),
    hovertemplate: [
      '<b>%{text}</b>',
      'Org: %{customdata[0]}',
      'Open Issues: %{customdata[3]}',
      'Avg CVSS: %{y:.2f}',
      'Critical: %{customdata[1]} · High: %{customdata[2]}',
      '<extra></extra>',
    ].join('<br>'),
  };

  Plotly.react('chart-scatter', [trace], layout({
    showlegend: false,
    margin:     { t: 20, r: 90, b: 55, l: 60 },
    xaxis:      { ...BASE_LAYOUT.xaxis, title: { text: 'Total Open Issues' } },
    yaxis:      { ...BASE_LAYOUT.yaxis, title: { text: 'Average CVSS Score' } },
    shapes: [
      { type: 'line', y0: 7.0, y1: 7.0, x0: 0, x1: 1, xref: 'paper',
        line: { color: 'red', dash: 'dash', width: 1, opacity: 0.45 } },
    ],
    annotations: [
      { y: 7.05, x: 0, xref: 'paper', text: 'High CVSS threshold (7.0)',
        showarrow: false, font: { size: 9, color: '#EF4444' }, xanchor: 'left' },
    ],
  }), PLOTLY_CONFIG);
}

/* ===================================================================
   Render All
   =================================================================== */
function renderAll() {
  const d = filteredData;
  updateKPIs(d);
  renderHeatmap(d);
  renderOrgTotals(d);
  renderSeverityBar(d);
  renderSeverityPie(d);
  renderTrend(d);
  renderScanType(d);
  renderScanSeverity(d);
  renderLanguage(d);
  renderCVSSBox(d);
  renderMTTRBar(d);
  renderMTTRViolin(d);
  renderFixability(d);
  renderExploit(d);
  renderCWE(d);
  renderScatter(d);
}

/* ===================================================================
   Initialisation
   =================================================================== */
function showDashboard() {
  document.getElementById('loading-overlay').classList.add('hidden');
  document.getElementById('upload-fallback').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
}

function showUploadFallback(errMsg) {
  document.getElementById('loading-overlay').classList.add('hidden');
  document.getElementById('upload-fallback').classList.remove('hidden');
  console.warn('Auto-load failed:', errMsg);
}

function onDataReady(data) {
  allData      = data;
  filteredData = [...allData];

  buildFilters(allData);
  updateHeaderSummary(allData);

  // Reset button
  const resetBtn = document.getElementById('reset-filters');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      activeOrgs      = new Set(['__all__']);
      activeScanTypes = new Set(['__all__']);
      document.querySelectorAll('.chip').forEach(c => {
        c.classList.toggle('active', c.dataset.value === '__all__');
      });
      filteredData = [...allData];
      renderAll();
    });
  }

  showDashboard();
  renderAll();
}

async function init() {
  // Try fetching the CSV
  try {
    const data = await loadDataFetch();
    onDataReady(data);
    return;
  } catch (err) {
    // fetch failed (likely file:// protocol restriction)
    showUploadFallback(err.message);
  }

  // File upload fallback
  const input = document.getElementById('csv-upload');
  if (input) {
    input.addEventListener('change', e => {
      const file = e.target.files[0];
      if (!file) return;

      document.getElementById('upload-fallback').classList.add('hidden');
      document.getElementById('loading-overlay').classList.remove('hidden');

      const reader = new FileReader();
      reader.onload = ev => {
        try {
          const data = parseCsv(ev.target.result);
          onDataReady(data);
        } catch (parseErr) {
          document.getElementById('loading-overlay').innerHTML =
            `<p style="color:#EF4444;font-weight:600">Failed to parse CSV: ${parseErr.message}</p>`;
        }
      };
      reader.readAsText(file);
    });
  }
}

document.addEventListener('DOMContentLoaded', init);
