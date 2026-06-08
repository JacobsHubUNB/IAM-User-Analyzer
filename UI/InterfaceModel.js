// ----------------------------------------------------------------
// loadPolicy: pulls the JSON file produced by Scripts/IAM.py
// (build_policy_dict) into the textarea so analyzePolicy can read it.
// Path is relative to index.html which lives in /UI/, so we step up
// one directory to reach /Scripts/.
// ----------------------------------------------------------------
async function loadPolicy() {
  const response = await fetch('policy_for_js.json');
  const data = await response.json();
  document.getElementById('policy-input').value = JSON.stringify(data, null, 2);
}

// Module-level state — held across re-analyses so the D3 simulation
// and SVG selection can be torn down and rebuilt on each click.
let graphData = { nodes: [], links: [] };
let allFindings = [];
let simulation = null;
let svg = null;
let zoomBehavior = null;
let g = null;

// shortName: trims an ARN down to a human label, so
// "arn:aws:s3:::my-bucket" displays as "my-bucket".
function shortName(arn) {
  if (!arn || arn === '*') return '*';
  const parts = arn.split(':');
  const last = parts[parts.length - 1];
  if (last.includes('/')) return last.split('/').pop();
  return last.length > 0 ? last : arn.substring(0, 24);
}

// ============================================================
// analyzePolicy: the heart of the app. Reads the IAM policy JSON
// from the textarea, walks every Statement, classifies risk,
// builds the graph data (nodes + links), and emits human-readable
// findings. Called on page load and whenever the user clicks
// "ANALYZE & VISUALIZE".
// ============================================================
function analyzePolicy() {
  const raw = document.getElementById('policy-input').value.trim();
  if (!raw) { alert('Please paste an IAM policy JSON first.'); return; }

  let policy;
  try { policy = JSON.parse(raw); }
  catch(e) { alert('Invalid JSON: ' + e.message); return; }

  const statements = policy.Statement || [];
  // Use a Map so adding the same node id twice is a no-op (dedup).
  // Without this we'd produce duplicate nodes whenever two statements
  // touch the same role, policy, or service.
  const nodes = new Map();
  const links = [];
  const findings = [];

  // addNode: idempotent insert. First call creates the node with
  // its label + metadata; later calls with the same id silently skip.
  // The trailing spread of `meta` lets callers override defaults
  // like `label` and `fullId`.
  function addNode(id, type, meta = {}) {
    if (!nodes.has(id)) nodes.set(id, { id, type, label: shortName(id), fullId: id, ...meta });
    return id;
  }

  statements.forEach((stmt, idx) => {
    const sid = stmt.Sid || `Stmt${idx}`;
    const effect = stmt.Effect || 'Allow';
    const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action].filter(Boolean);
    const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource].filter(Boolean);

    // ----------------------------------------------------------------
    // Principal extraction — AWS allows three shapes here:
    //   1) "*"                              → public, anyone
    //   2) "arn:aws:iam::123:role/x"        → a single ARN as a string
    //   3) { "AWS": [...], "Service": ... } → an object grouping principals by type
    // We flatten all of them into a single list so downstream code
    // doesn't have to care about the shape.
    // ----------------------------------------------------------------
    let principals = [];
    if (stmt.Principal) {
      const p = stmt.Principal;
      if (p === '*') principals = ['*'];
      else if (typeof p === 'string') principals = [p];
      else {
        Object.values(p).forEach(v => {
          if (Array.isArray(v)) principals.push(...v);
          else principals.push(v);
        });
      }
    }

    // Detect role type
    const getRoleType = (arn) => {
      if (arn === '*') return 'Anyone';
      if (arn.includes('service')) return 'Service';
      if (arn.includes('role')) return 'Role';
      if (arn.includes('user')) return 'User';
      return 'Principal';
    };

    // ----------------------------------------------------------------
    // Risk is no longer computed here — Python's classify_risk() is the
    // single source of truth. We just read stmt.Risk (HIGH/MEDIUM/LOW/DENY)
    // and stmt.RiskReason (short human-readable explanation) and propagate
    // them onto the policy node and every outgoing edge, where the visual
    // layer (nodeColor / nodeBorder / edge stroke + tooltip) consumes them.
    // ----------------------------------------------------------------
    const riskLevel = stmt.Risk || 'LOW';
    const riskReason = stmt.RiskReason || '';
    const isDeny = riskLevel === 'DENY' || effect === 'Deny';
    const isHigh = riskLevel === 'HIGH';
    const isMedium = riskLevel === 'MEDIUM';
    // Wildcard is still useful for the icon color on Policy nodes.
    const hasWildcardAction = actions.some(a => a === '*' || a.endsWith(':*'));

    // Add policy node
    const policyNodeId = `policy:${sid}`;
    addNode(policyNodeId, 'Policy', {
      actions,
      resources,
      effect,
      riskLevel,
      riskReason,
      isWildcard: hasWildcardAction,
      isCritical: isHigh,
      isWarning: isMedium,
      sid
    });

    // Add principal → policy edges. Risk rides on the edge so the tooltip
    // and stroke color can both consume it.
    principals.forEach(principal => {
      const pId = addNode(principal, getRoleType(principal), { isExternal: principal.includes('987654321098') });
      links.push({
        source: pId,
        target: policyNodeId,
        effect,
        label: effect,
        isDeny,
        riskLevel,
        riskReason,
        actions,
        sid
      });
    });
    // ----------------------------------------------------------------
    // RESOURCE AGGREGATION BY AWS SERVICE
    // A broad policy can list hundreds of resource ARNs. Rendering
    // one graph node per ARN turns the canvas into an unreadable
    // "hairball." Instead we bucket this statement's ARNs by service
    // (the 3rd colon-segment of an ARN: arn:aws:<service>:...) and
    // emit ONE node per (statement, service) pair. The full ARN list
    // rides along in node.arns so the hover-tooltip can show every
    // entry on demand — overview on the canvas, detail one hover away.
    // ----------------------------------------------------------------
    const resourcesByService = {};
    resources.forEach(resource => {
      const service = resource === '*' ? 'all-services' : (resource.split(':')[2] || 'unknown');
      if (!resourcesByService[service]) resourcesByService[service] = [];
      resourcesByService[service].push(resource);
    });

    Object.entries(resourcesByService).forEach(([service, arns]) => {
      // Scope the node id per-statement so two statements that both
      // touch s3 get distinct nodes, each carrying its own ARN list.
      const serviceNodeId = `service:${sid}:${service}`;
      addNode(serviceNodeId, 'Resource', {
        service,
        arns,
        // label overrides shortName(id); shows "<service> (<count>)" on the canvas
        label: service === 'all-services' ? '* (all)' : `${service} (${arns.length})`,
        fullId: `${service} → ${arns.length} resource${arns.length === 1 ? '' : 's'}`,
      });
      links.push({
        source: policyNodeId,
        target: serviceNodeId,
        actions: actions.slice(0, 3),
        effect,
        isDeny,
        riskLevel,
        riskReason,
        sid
      });
    });

    // ----------------------------------------------------------------
    // FINDINGS — derived directly from Python's risk verdict.
    // HIGH → critical card, MEDIUM → warning card, LOW/DENY → no card.
    // Special-case: a public principal ("*") is a critical finding even
    // if Python classified the rest of the statement as low risk, because
    // Python only sees identity-attached policies (no Principal field).
    // ----------------------------------------------------------------
    if (riskLevel === 'HIGH') {
      findings.push({
        severity: 'critical',
        title: `HIGH risk in "${sid}"`,
        detail: riskReason || 'High-impact permission combination detected.',
        sid,
        principals
      });
    } else if (riskLevel === 'MEDIUM') {
      findings.push({
        severity: 'warning',
        title: `MEDIUM risk in "${sid}"`,
        detail: riskReason || 'Broad permission scope detected.',
        sid,
        principals
      });
    }

    if (principals.includes('*') && !isDeny) {
      findings.push({
        severity: 'critical',
        title: `Public Principal (*) in "${sid}"`,
        detail: `Policy allows ANY principal (including unauthenticated). This effectively makes resources publicly accessible.`,
        sid,
        principals
      });
    }
  });

  graphData = {
    nodes: Array.from(nodes.values()),
    links
  };
  allFindings = findings;

  // Update stats
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const warnCount = findings.filter(f => f.severity === 'warning').length;
  document.getElementById('stat-nodes').textContent = graphData.nodes.length;
  document.getElementById('stat-edges').textContent = links.length;
  document.getElementById('stat-warnings').textContent = warnCount;
  document.getElementById('stat-critical').textContent = critCount;

  renderFindings(findings);
  renderGraph(graphData);
  document.getElementById('empty-state').style.display = 'none';
}

function renderFindings(findings) {
  const el = document.getElementById('findings-list');
  if (findings.length === 0) {
    el.innerHTML = '<div class="no-findings" style="margin-top:24px;"><div style="font-size:24px;margin-bottom:8px;">✅</div>No security issues found</div>';
    return;
  }

  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2 };
    return order[a.severity] - order[b.severity];
  });

  el.innerHTML = sorted.map((f, i) => `
    <div class="finding ${f.severity}" style="animation-delay:${i*0.05}s" onclick="highlightSid('${f.sid}')">
      <div class="finding-badge ${f.severity}">
        ${f.severity === 'critical' ? '⬥ CRITICAL' : f.severity === 'warning' ? '◆ WARNING' : '● INFO'}
      </div>
      <div class="finding-title">${f.title}</div>
      <div class="finding-detail">${f.detail}</div>
    </div>
  `).join('');
}

// ============================
// D3 GRAPH
// ============================
function renderGraph(data) {
  const container = document.getElementById('graph-container');
  const W = container.clientWidth;
  const H = container.clientHeight;

  d3.select('#graph-svg').selectAll('*').remove();

  svg = d3.select('#graph-svg');
  zoomBehavior = d3.zoom().scaleExtent([0.2, 4]).on('zoom', (e) => g.attr('transform', e.transform));
  svg.call(zoomBehavior);

  // Defs — one arrow marker per risk tier so edges visually announce their classification.
  //   arrow-low  = cyan (existing safe-default look)
  //   arrow-med  = amber  (MEDIUM)
  //   arrow-high = red    (HIGH)
  //   arrow-deny = slate  (protective Deny — muted, not alarming)
  const defs = svg.append('defs');
  defs.append('marker').attr('id', 'arrow-low')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(0,212,255,0.5)');
  defs.append('marker').attr('id', 'arrow-med')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(255,182,39,0.85)');
  defs.append('marker').attr('id', 'arrow-high')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(255,58,58,0.9)');
  defs.append('marker').attr('id', 'arrow-deny')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(120,140,165,0.6)');

  // Glow filter
  const filt = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
  filt.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
  const feMerge = filt.append('feMerge');
  feMerge.append('feMergeNode').attr('in', 'blur');
  feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

  g = svg.append('g');

  // Force sim — high-risk edges pull endpoints in tighter so the danger clusters together.
  simulation = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.links).id(d => d.id).distance(d => {
      if (d.riskLevel === 'HIGH') return 90;
      if (d.riskLevel === 'MEDIUM') return 105;
      return 120;
    }).strength(0.6))
    .force('charge', d3.forceManyBody().strength(-280))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide(40));

  // ----------------------------------------------------------------
  // Edge styling helpers — single risk-tier lookup keeps stroke,
  // width, and marker in lockstep so they can never disagree visually.
  // ----------------------------------------------------------------
  function edgeStroke(d) {
    if (d.riskLevel === 'DENY' || d.isDeny) return 'rgba(120,140,165,0.55)';
    if (d.riskLevel === 'HIGH') return 'rgba(255,58,58,0.75)';
    if (d.riskLevel === 'MEDIUM') return 'rgba(255,182,39,0.7)';
    return 'rgba(0,212,255,0.25)';
  }
  function edgeWidth(d) {
    if (d.riskLevel === 'HIGH') return 2.5;
    if (d.riskLevel === 'MEDIUM') return 2;
    return 1;
  }
  function edgeMarker(d) {
    if (d.riskLevel === 'DENY' || d.isDeny) return 'url(#arrow-deny)';
    if (d.riskLevel === 'HIGH') return 'url(#arrow-high)';
    if (d.riskLevel === 'MEDIUM') return 'url(#arrow-med)';
    return 'url(#arrow-low)';
  }

  // Visible link lines — wrapped in a classed container so applyFilter can target them.
  const link = g.append('g').attr('class', 'links').selectAll('line')
    .data(data.links).join('line')
    .attr('stroke', edgeStroke)
    .attr('stroke-width', edgeWidth)
    .attr('stroke-dasharray', d => (d.riskLevel === 'DENY' || d.isDeny) ? '4 3' : null)
    .attr('marker-end', edgeMarker);

  // Invisible "hit-area" lines sitting directly on top of the visible edges.
  // Lines are thin (1-2.5px) and hard to hover — this fat transparent overlay
  // gives the cursor a forgiving 12px target so the edge tooltip actually triggers.
  const linkHitArea = g.append('g').attr('class', 'link-hit').selectAll('line')
    .data(data.links).join('line')
    .attr('stroke', 'transparent')
    .attr('stroke-width', 12)
    .style('cursor', 'pointer');

  // Link labels — same classing pattern for the filter.
  const linkLabel = g.append('g').attr('class', 'link-labels').selectAll('text')
    .data(data.links.filter(l => l.actions && l.actions.length > 0)).join('text')
    .attr('font-size', '7.5px')
    .attr('fill', 'rgba(167,139,250,0.55)')
    .attr('font-family', 'JetBrains Mono, monospace')
    .text(d => d.actions ? d.actions[0] + (d.actions.length > 1 ? ` +${d.actions.length-1}` : '') : d.label || '');

  // Nodes — each per-node <g> gets class="node" so applyFilter can grab them with g.selectAll('g.node').
  const nodeGroup = g.append('g').selectAll('g')
    .data(data.nodes).join('g')
    .classed('node', true)
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

  // Risk tier wins over node type for the fill / border colors. The palette
  // mirrors the new purple/blue dark theme — deep saturated fills, bright
  // accented borders, so a HIGH-risk node looks unmistakably red and a
  // healthy Policy node sits in a clean purple tone.
  function nodeColor(d) {
    if (d.riskLevel === 'HIGH' || d.isCritical) return 'rgba(127,29,29,0.85)';     // deep red
    if (d.riskLevel === 'MEDIUM' || d.isWarning) return 'rgba(133,77,14,0.8)';     // deep amber
    if (d.riskLevel === 'DENY') return 'rgba(51,65,85,0.85)';                       // slate
    if (d.type === 'Role' || d.type === 'User') return 'rgba(30,41,95,0.9)';        // deep blue
    if (d.type === 'Policy') return 'rgba(54,25,92,0.9)';                           // deep purple
    if (d.type === 'Service') return 'rgba(22,78,99,0.9)';                          // deep cyan
    if (d.type === 'Resource') return 'rgba(15,76,56,0.9)';                         // deep emerald
    if (d.type === 'Anyone') return 'rgba(127,29,29,0.9)';                          // deep red
    return 'rgba(30,32,60,0.9)';
  }

  function nodeBorder(d) {
    if (d.riskLevel === 'HIGH' || d.isCritical) return '#f87171';                   // soft red
    if (d.riskLevel === 'MEDIUM' || d.isWarning) return '#fbbf24';                  // amber
    if (d.riskLevel === 'DENY') return 'rgba(148,163,184,0.7)';                     // slate
    if (d.type === 'Role' || d.type === 'User') return 'rgba(96,165,250,0.8)';      // blue
    if (d.type === 'Policy') return d.isWildcard ? 'rgba(251,191,36,0.7)' : 'rgba(167,139,250,0.75)'; // purple
    if (d.type === 'Service') return 'rgba(34,211,238,0.75)';                       // cyan
    if (d.type === 'Resource') return 'rgba(52,211,153,0.75)';                      // emerald
    if (d.type === 'Anyone') return '#f87171';
    return 'rgba(167,139,250,0.4)';
  }

  function nodeSize(d) {
    if (d.type === 'Role' || d.type === 'User' || d.type === 'Anyone' || d.type === 'Service') return 22;
    if (d.type === 'Policy') return 18;
    return 16;
  }

  function nodeIcon(d) {
    if (d.type === 'Anyone') return '★';
    if (d.type === 'Role') return '⬡';
    if (d.type === 'User') return '◈';
    if (d.type === 'Service') return '⬢';
    if (d.type === 'Policy') return d.effect === 'Deny' ? '✕' : '⬥';
    if (d.type === 'Resource') {
      const s = d.service || '';
      if (s === 's3') return '▣';
      if (s === 'ec2') return '▤';
      if (s === 'iam') return '◉';
      if (s === 'lambda') return 'λ';
      if (s === 'dynamodb') return '⊞';
      return '◆';
    }
    return '●';
  }

  // Rect nodes
  nodeGroup.append('rect')
    .attr('width', d => nodeSize(d) * 2 + 20)
    .attr('height', d => nodeSize(d) * 2)
    .attr('x', d => -(nodeSize(d) + 10))
    .attr('y', d => -nodeSize(d))
    .attr('rx', 4)
    .attr('fill', nodeColor)
    .attr('stroke', nodeBorder)
    .attr('stroke-width', d => (d.riskLevel === 'HIGH' || d.riskLevel === 'MEDIUM' || d.isCritical) ? 1.5 : 1)
    // Glow only on HIGH-risk nodes so they really pop in the hairball.
    .attr('filter', d => (d.riskLevel === 'HIGH' || d.isCritical) ? 'url(#glow)' : null);

  // Icon glyph color — risk tier overrides type so the icon matches the surrounding red/amber.
  nodeGroup.append('text')
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'central')
    .attr('y', -4)
    .attr('font-size', d => nodeSize(d) * 0.65 + 'px')
    .attr('fill', d => {
      if (d.riskLevel === 'HIGH' || d.isCritical || d.type === 'Anyone') return '#fca5a5';
      if (d.riskLevel === 'MEDIUM' || d.isWarning) return '#fcd34d';
      if (d.type === 'Role' || d.type === 'User') return '#93c5fd';
      if (d.type === 'Policy') return d.isWildcard ? '#fcd34d' : '#c4b5fd';
      if (d.type === 'Service') return '#67e8f9';
      return '#6ee7b7';
    })
    .text(nodeIcon);

  // Label below each node — slightly brighter than before so labels read against the dark canvas.
  nodeGroup.append('text')
    .attr('text-anchor', 'middle')
    .attr('y', d => nodeSize(d) + 14)
    .attr('font-size', '9.5px')
    .attr('fill', 'rgba(196,181,253,0.75)')
    .attr('font-family', 'JetBrains Mono, monospace')
    .text(d => d.label.length > 14 ? d.label.substring(0, 13) + '…' : d.label);

  // ----------------------------------------------------------------
  // Tooltip = the floating info-card that appears next to the cursor
  // when you hover a node. The empty <div id="tooltip"></div> lives in
  // index.html; we fill its innerHTML on mouseover, move it with the
  // cursor on mousemove, and hide it on mouseout. The new `d.arns`
  // block is what unlocks the aggregation trick: a service node
  // labeled "apigateway (50)" on the canvas reveals every one of its
  // 50 ARNs in a scrollable list here (capped at 25 with a "…and N more"
  // tail so the tooltip stays a sane size).
  // ----------------------------------------------------------------
  const tooltip = document.getElementById('tooltip');

  // Shared helper — color the "risk badge" line in the tooltip header.
  function riskColor(level) {
    if (level === 'HIGH') return 'var(--critical)';
    if (level === 'MEDIUM') return 'var(--warn)';
    if (level === 'DENY')  return 'rgba(140,160,190,0.9)';
    return 'var(--accent3)';
  }
  function positionTooltip(event) {
    const x = event.pageX + 14;
    const y = event.pageY - 10;
    tooltip.style.left = Math.min(x, window.innerWidth - 340) + 'px';
    tooltip.style.top = y + 'px';
  }

  // ----------------------------------------------------------------
  // NODE TOOLTIP — fires when hovering a graph node. Renders into
  // #tooltip in index.html, then we position it next to the cursor.
  // The d.arns block is the aggregation drill-down (clean canvas
  // node like "apigateway (50)" reveals the full ARN list here).
  // ----------------------------------------------------------------
  nodeGroup
    .on('mouseover', function(event, d) {
      const actions = d.actions || [];
      const tier = d.riskLevel || (d.isCritical ? 'HIGH' : null);
      tooltip.innerHTML = `
        <div class="tt-name">${d.fullId || d.id}</div>
        <div class="tt-type" style="color: ${tier ? riskColor(tier) : 'var(--muted)'}">${d.type}${tier ? ' • ' + tier : ''}${d.isCritical && !tier ? ' ⚠ CRITICAL' : ''}</div>
        ${d.riskReason ? `<div class="tt-row"><span>Reason</span><span>${d.riskReason}</span></div>` : ''}
        ${d.effect ? `<div class="tt-row"><span>Effect</span><span style="color:${d.effect==='Deny'?'var(--critical)':'var(--accent3)'}">${d.effect}</span></div>` : ''}
        ${d.service ? `<div class="tt-row"><span>Service</span><span>${d.service}</span></div>` : ''}
        ${actions.length ? `<div class="tt-actions"><div style="font-size:8px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.1em;">Actions</div>
          ${actions.map(a => `<span class="tt-action-chip ${a==='*'||a.endsWith(':*')||a.includes('iam:')||a.includes('sts:')?'danger':''}">${a}</span>`).join('')}
        </div>` : ''}
        ${d.arns ? `<div class="tt-actions" style="margin-top:8px;">
          <div style="font-size:8px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.1em;">Resources (${d.arns.length})</div>
          <div style="max-height:180px;overflow-y:auto;font-size:9px;font-family:JetBrains Mono,monospace;line-height:1.4;">
            ${d.arns.slice(0, 25).map(a => `<div style="padding:1px 0;color:var(--muted);word-break:break-all;">${a}</div>`).join('')}
            ${d.arns.length > 25 ? `<div style="padding:4px 0;color:#ffb627;">…and ${d.arns.length - 25} more</div>` : ''}
          </div>
        </div>` : ''}
      `;
      tooltip.classList.add('visible');
    })
    .on('mousemove', positionTooltip)
    .on('mouseout', () => tooltip.classList.remove('visible'));

  // ----------------------------------------------------------------
  // EDGE TOOLTIP — same #tooltip element, different content.
  // Bound to the fat invisible hit-area lines (not the thin visible
  // ones, which are too hard to hover). Shows the risk tier, the
  // reason from Python, the effect, and the action list.
  // ----------------------------------------------------------------
  linkHitArea
    .on('mouseover', function(event, d) {
      const tier = d.riskLevel || 'LOW';
      const actions = d.actions || [];
      tooltip.innerHTML = `
        <div class="tt-name">Permission Edge</div>
        <div class="tt-type" style="color: ${riskColor(tier)}">${tier}${d.isDeny ? ' • DENY' : ''}</div>
        ${d.riskReason ? `<div class="tt-row"><span>Reason</span><span>${d.riskReason}</span></div>` : ''}
        <div class="tt-row"><span>Effect</span><span style="color:${d.effect==='Deny'?'var(--critical)':'var(--accent3)'}">${d.effect || 'Allow'}</span></div>
        ${d.sid ? `<div class="tt-row"><span>Statement</span><span>${d.sid}</span></div>` : ''}
        ${actions.length ? `<div class="tt-actions"><div style="font-size:8px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.1em;">Actions</div>
          ${actions.map(a => `<span class="tt-action-chip ${a==='*'||a.endsWith(':*')||a.includes('iam:')||a.includes('sts:')?'danger':''}">${a}</span>`).join('')}
        </div>` : ''}
      `;
      tooltip.classList.add('visible');
    })
    .on('mousemove', positionTooltip)
    .on('mouseout', () => tooltip.classList.remove('visible'));

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    // Keep the invisible hit-area lines glued to their visible siblings.
    linkHitArea
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    linkLabel
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2 - 4);

    nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Auto-fit after settle
  setTimeout(() => {
    const bounds = g.node().getBBox();
    const fullW = container.clientWidth;
    const fullH = container.clientHeight;
    const scale = Math.min(fullW / (bounds.width + 80), fullH / (bounds.height + 80), 1.2);
    const tx = fullW / 2 - scale * (bounds.x + bounds.width / 2);
    const ty = fullH / 2 - scale * (bounds.y + bounds.height / 2);
    svg.transition().duration(600).call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }, 1200);
}

function highlightSid(sid) {
  // Pulse the matching policy node — uses the same risk-aware stroke width
  // we apply at render time so the restore call doesn't visually flatten
  // a HIGH/MEDIUM node back down to a normal one.
  if (!g) return;
  const riskStroke = d => (d.riskLevel === 'HIGH' || d.riskLevel === 'MEDIUM' || d.isCritical) ? 1.5 : 1;
  g.selectAll('rect')
    .attr('stroke-width', d => d.sid === sid ? 2.5 : riskStroke(d))
    .attr('stroke', d => d.sid === sid ? '#fff' : null);
  setTimeout(() => {
    g.selectAll('rect').attr('stroke-width', riskStroke).attr('stroke', null);
  }, 1500);
}

// ----------------------------------------------------------------
// applyFilter: dim everything that doesn't match the dropdown.
//   • shouldShow(d) is the single source of truth — both nodes and
//     edges use it so they stay in sync.
//   • Edges fade when EITHER endpoint is hidden, otherwise you'd see
//     half-edges floating into faded nodes.
//   • "Identities" covers every principal-flavored type the analyzer
//     emits (Role / User / Service / Anyone / Principal), since
//     getRoleType() spreads principals across all of them.
// ----------------------------------------------------------------
function applyFilter() {
  const val = document.getElementById('filter-type').value;
  if (!g) return;

  const identityTypes = new Set(['Role', 'User', 'Service', 'Anyone', 'Principal']);

  function shouldShow(d) {
    // D3 force-link replaces source/target string ids with node objects after
    // the simulation starts; before that they're raw strings. Guard either way.
    if (!d || typeof d === 'string') return true;
    if (val === 'All Nodes') return true;
    if (val === 'Critical') return !!d.isCritical;
    if (val === 'Identities') return identityTypes.has(d.type);
    if (val === 'Policies') return d.type === 'Policy';
    if (val === 'Resource') return d.type === 'Resource';
    return true;
  }

  // Fade non-matching nodes.
  g.selectAll('g.node').style('opacity', d => shouldShow(d) ? 1 : 0.15);
  // Fade edges where either endpoint is hidden.
  g.selectAll('g.links line').style('opacity', d => (shouldShow(d.source) && shouldShow(d.target)) ? 1 : 0.08);
  // Edge labels follow their edges.
  g.selectAll('g.link-labels text').style('opacity', d => (shouldShow(d.source) && shouldShow(d.target)) ? 1 : 0.08);
  // Disable pointer events on hit-areas of hidden edges so tooltips don't fire over faded lines.
  g.selectAll('g.link-hit line').style('pointer-events', d => (shouldShow(d.source) && shouldShow(d.target)) ? 'auto' : 'none');
}

function zoomIn() { if (svg && zoomBehavior) svg.transition().call(zoomBehavior.scaleBy, 1.4); }
function zoomOut() { if (svg && zoomBehavior) svg.transition().call(zoomBehavior.scaleBy, 0.7); }
function resetZoom() {
  if (svg && zoomBehavior) svg.transition().duration(500).call(zoomBehavior.transform, d3.zoomIdentity.translate(
    document.getElementById('graph-container').clientWidth / 2,
    document.getElementById('graph-container').clientHeight / 2
  ).scale(0.9));
}

// Auto-load wildcard example
window.addEventListener('load', () => {
  loadPolicy();
  setTimeout(analyzePolicy, 200);
});
