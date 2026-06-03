// ----------------------------------------------------------------
// loadPolicy: pulls the JSON file produced by Scripts/IAM.py
// (build_policy_dict) into the textarea so analyzePolicy can read it.
// Path is relative to index.html which lives in /UI/, so we step up
// one directory to reach /Scripts/.
// ----------------------------------------------------------------
async function loadPolicy() {
  const response = await fetch('../Scripts/policy_for_js.json');
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
    // Risk flags — each one is a heuristic for a known IAM antipattern:
    //   hasWildcardAction:   any action is "*" or ends with ":*" (e.g. "s3:*")
    //   hasWildcardResource: any resource is "*"
    //   hasBothWildcards:    root-equivalent access if not denied
    //   hasIAMWrite:         can mutate IAM itself → privilege-escalation risk
    //   hasSTSAssume:        can assume other roles → lateral-movement risk
    //   hasSecretsAccess:    can read secrets / SSM parameters
    //   isDeny:              Deny overrides Allow, so we suppress findings
    //                        on Deny rows (they're protective, not risky).
    // ----------------------------------------------------------------
    const hasWildcardAction = actions.some(a => a === '*' || a.endsWith(':*'));
    const hasWildcardResource = resources.some(r => r === '*');
    const hasBothWildcards = hasWildcardAction && hasWildcardResource;
    const hasIAMWrite = actions.some(a => a.includes('iam:') && (a.includes('Create') || a.includes('Put') || a.includes('Pass') || a === 'iam:*'));
    const hasSTSAssume = actions.some(a => a.includes('sts:AssumeRole'));
    const hasSecretsAccess = actions.some(a => a.includes('secretsmanager:') || a.includes('ssm:Get'));
    const isDeny = effect === 'Deny';

    // Add policy node
    const policyNodeId = `policy:${sid}`;
    addNode(policyNodeId, 'Policy', {
      actions,
      resources,
      effect,
      isWildcard: hasWildcardAction,
      isCritical: hasBothWildcards || hasIAMWrite,
      sid
    });

    // Add principal → policy edges
    principals.forEach(principal => {
      const pId = addNode(principal, getRoleType(principal), { isExternal: principal.includes('987654321098') });
      links.push({
        source: pId,
        target: policyNodeId,
        effect,
        label: effect,
        isDeny,
        isCritical: hasBothWildcards || hasIAMWrite
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
        isCritical: hasBothWildcards || (hasWildcardAction && !isDeny)
      });
    });

    // FINDINGS
    if (hasBothWildcards && !isDeny) {
      findings.push({
        severity: 'critical',
        title: `Wildcard Action + Resource in "${sid}"`,
        detail: `Principal(s) have unrestricted access to ALL services and ALL resources. This is equivalent to root-level access.`,
        sid,
        principals
      });
    } else if (hasWildcardAction && !isDeny) {
      findings.push({
        severity: 'critical',
        title: `Wildcard Action (*) in "${sid}"`,
        detail: `All actions allowed on: ${resources.slice(0,2).join(', ')}. Violates least-privilege principle.`,
        sid,
        principals
      });
    }

    if (hasIAMWrite && !isDeny) {
      findings.push({
        severity: 'critical',
        title: `IAM Write Permissions in "${sid}"`,
        detail: `IAM mutations (${actions.filter(a => a.startsWith('iam:')).join(', ')}) allow privilege escalation. A role can grant itself or others elevated permissions.`,
        sid,
        principals
      });
    }

    if (hasSTSAssume && !isDeny) {
      findings.push({
        severity: 'warning',
        title: `Cross-Account Role Assumption in "${sid}"`,
        detail: `sts:AssumeRole detected. Verify the trusted principal is intentional and MFA is required for sensitive roles.`,
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

    if (hasSecretsAccess && hasWildcardResource && !isDeny) {
      findings.push({
        severity: 'warning',
        title: `Broad Secrets Access in "${sid}"`,
        detail: `Access to secrets/SSM parameters on wildcard resource. Scope down to specific secret ARNs.`,
        sid,
        principals
      });
    }

    if (resources.some(r => r === '*') && !hasWildcardAction && !isDeny) {
      findings.push({
        severity: 'warning',
        title: `Wildcard Resource in "${sid}"`,
        detail: `Actions (${actions.slice(0,2).join(', ')}) apply to ALL resources of that type. Consider scoping to specific ARNs.`,
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

  // Defs
  const defs = svg.append('defs');
  defs.append('marker').attr('id', 'arrow-allow')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(0,212,255,0.5)');
  defs.append('marker').attr('id', 'arrow-deny')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(255,58,58,0.6)');
  defs.append('marker').attr('id', 'arrow-critical')
    .attr('viewBox', '0 -4 8 8').attr('refX', 14).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(255,182,39,0.8)');

  // Glow filter
  const filt = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
  filt.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
  const feMerge = filt.append('feMerge');
  feMerge.append('feMergeNode').attr('in', 'blur');
  feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

  g = svg.append('g');

  // Force sim
  simulation = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.links).id(d => d.id).distance(d => {
      if (d.isCritical) return 90;
      return 120;
    }).strength(0.6))
    .force('charge', d3.forceManyBody().strength(-280))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide(40));

  // Links
  const link = g.append('g').selectAll('line')
    .data(data.links).join('line')
    .attr('stroke', d => d.isDeny ? 'rgba(255,58,58,0.5)' : d.isCritical ? 'rgba(255,182,39,0.6)' : 'rgba(0,212,255,0.25)')
    .attr('stroke-width', d => d.isCritical ? 2 : 1)
    .attr('stroke-dasharray', d => d.isDeny ? '4 3' : null)
    .attr('marker-end', d => d.isDeny ? 'url(#arrow-deny)' : d.isCritical ? 'url(#arrow-critical)' : 'url(#arrow-allow)');

  // Link labels
  const linkLabel = g.append('g').selectAll('text')
    .data(data.links.filter(l => l.actions && l.actions.length > 0)).join('text')
    .attr('font-size', '7px')
    .attr('fill', 'rgba(74,100,128,0.8)')
    .attr('font-family', 'JetBrains Mono, monospace')
    .text(d => d.actions ? d.actions[0] + (d.actions.length > 1 ? ` +${d.actions.length-1}` : '') : d.label || '');

  // Nodes
  const nodeGroup = g.append('g').selectAll('g')
    .data(data.nodes).join('g')
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

  function nodeColor(d) {
    if (d.isCritical) return 'rgba(120,30,30,0.8)';
    if (d.type === 'Role' || d.type === 'User') return 'rgba(30,77,140,0.9)';
    if (d.type === 'Policy') return 'rgba(61,32,96,0.9)';
    if (d.type === 'Service') return 'rgba(30,77,80,0.9)';
    if (d.type === 'Resource') return 'rgba(26,61,43,0.9)';
    if (d.type === 'Anyone') return 'rgba(140,30,30,0.9)';
    return 'rgba(30,50,70,0.9)';
  }

  function nodeBorder(d) {
    if (d.isCritical) return '#ff3a3a';
    if (d.type === 'Role' || d.type === 'User') return 'rgba(45,107,181,0.8)';
    if (d.type === 'Policy') return d.isWildcard ? 'rgba(255,182,39,0.7)' : 'rgba(96,48,160,0.7)';
    if (d.type === 'Service') return 'rgba(45,120,130,0.7)';
    if (d.type === 'Resource') return 'rgba(42,96,69,0.7)';
    if (d.type === 'Anyone') return '#ff3a3a';
    return 'rgba(40,70,100,0.7)';
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
    .attr('stroke-width', d => d.isCritical ? 1.5 : 1)
    .attr('filter', d => d.isCritical ? 'url(#glow)' : null);

  // Icon
  nodeGroup.append('text')
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'central')
    .attr('y', -4)
    .attr('font-size', d => nodeSize(d) * 0.65 + 'px')
    .attr('fill', d => {
      if (d.isCritical || d.type === 'Anyone') return '#ff6060';
      if (d.type === 'Role' || d.type === 'User') return '#4da6ff';
      if (d.type === 'Policy') return d.isWildcard ? var_warn : '#a060ff';
      if (d.type === 'Service') return '#40c0c0';
      return '#40a060';
    })
    .text(nodeIcon);

  function var_warn() { return '#ffb627'; }

  // Label
  nodeGroup.append('text')
    .attr('text-anchor', 'middle')
    .attr('y', d => nodeSize(d) + 12)
    .attr('font-size', '9px')
    .attr('fill', '#8899aa')
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
  nodeGroup
    .on('mouseover', function(event, d) {
      const actions = d.actions || [];
      const hasDanger = actions.some(a => a === '*' || a.endsWith(':*') || a.startsWith('iam:') || a.startsWith('sts:'));
      tooltip.innerHTML = `
        <div class="tt-name">${d.fullId || d.id}</div>
        <div class="tt-type" style="color: ${d.isCritical ? 'var(--critical)' : 'var(--muted)'}">${d.type} ${d.isCritical ? '⚠ CRITICAL' : ''}</div>
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
    .on('mousemove', function(event) {
      const x = event.pageX + 14;
      const y = event.pageY - 10;
      tooltip.style.left = Math.min(x, window.innerWidth - 300) + 'px';
      tooltip.style.top = y + 'px';
    })
    .on('mouseout', function() {
      tooltip.classList.remove('visible');
    });

  simulation.on('tick', () => {
    link
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
  // Pulse the matching policy node
  if (!g) return;
  g.selectAll('rect').attr('stroke-width', d => d.sid === sid ? 2.5 : (d.isCritical ? 1.5 : 1))
    .attr('stroke', d => d.sid === sid ? '#fff' : null);
  setTimeout(() => {
    g.selectAll('rect').attr('stroke-width', d => d.isCritical ? 1.5 : 1).attr('stroke', null);
  }, 1500);
}

function applyFilter() {
  const val = document.getElementById('filter-type').value;
  if (!g) return;
  g.selectAll('g').style('opacity', d => {
    if (val === 'all') return 1;
    if (val === 'critical') return d.isCritical ? 1 : 0.15;
    return d.type === val ? 1 : 0.15;
  });
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
