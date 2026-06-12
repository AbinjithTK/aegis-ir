"""Add Cases, Live Traces, and Accuracy pages to dashboard."""

path = r'F:\Abin\Sifthack\aegis-ir\src\sift_defender\web\templates\dashboard.html'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Add pages before the modal (find the modal div and insert before it)
pages_html = '''
        <!-- CASES PAGE -->
        <div id="page-cases" class="hidden fade-up">
            <div class="page-header"><h1>Cases</h1><p>All investigations — click to view details</p></div>
            <div class="card"><div class="card-head"><span>Investigation History</span><i data-lucide="history"></i></div><div class="card-body" id="full-cases-list"><div class="empty"><i data-lucide="folder-open"></i><h3>Loading cases...</h3></div></div></div>
        </div>

        <!-- LIVE TRACES PAGE -->
        <div id="page-traces" class="hidden fade-up">
            <div class="page-header"><h1>Live Traces</h1><p>Real-time Phoenix trace spans from active investigations</p></div>
            <div class="card"><div class="card-head"><span>Trace Timeline</span><span class="live" id="trace-live">Live</span></div><div class="card-body" id="trace-feed" style="min-height:300px"><div class="empty"><i data-lucide="activity"></i><h3>No active traces</h3><p>Start an investigation to see traces flow in real-time</p></div></div></div>
            <div class="card" style="margin-top:12px"><div class="card-head"><span>Phoenix Info</span><i data-lucide="eye"></i></div><div class="card-body"><div class="two-col"><div><div class="form-label">Mode</div><div id="trace-mode" style="font-size:12px;color:var(--text-secondary)">—</div></div><div><div class="form-label">Project</div><div id="trace-project" style="font-size:12px;color:var(--text-secondary)">—</div></div></div><p style="font-size:11px;color:var(--text-muted);margin-top:12px">All agent tool calls, LLM reasoning, and guardrail evaluations are traced through Phoenix. In memory mode, traces are collected in-process. In cloud mode, they stream to Arize Phoenix for persistent analysis.</p></div></div>
        </div>

        <!-- ACCURACY PAGE -->
        <div id="page-accuracy" class="hidden fade-up">
            <div class="page-header"><h1>Accuracy</h1><p>Guardrail pipeline performance — hallucination detection rates</p></div>
            <div class="metrics" style="grid-template-columns:repeat(3,1fr)">
                <div class="metric"><div class="metric-icon green"><i data-lucide="check-circle"></i></div><div class="metric-val green" id="acc-approved">—</div><div class="metric-label">Approved (factual)</div></div>
                <div class="metric"><div class="metric-icon yellow"><i data-lucide="alert-triangle"></i></div><div class="metric-val yellow" id="acc-flagged">—</div><div class="metric-label">Flagged for review</div></div>
                <div class="metric"><div class="metric-icon red"><i data-lucide="x-circle"></i></div><div class="metric-val red" id="acc-blocked">—</div><div class="metric-label">Blocked (hallucinated)</div></div>
            </div>
            <div class="card"><div class="card-head"><span>How It Works</span><i data-lucide="shield"></i></div><div class="card-body"><p style="font-size:12px;color:var(--text-secondary);line-height:1.8">Every finding produced by the AEGIS-IR agent passes through the <strong style="color:var(--text)">Guardrail Pipeline</strong> before reaching analysts:<br><br><span class="badge badge-green">APPROVE</span> Finding is backed by evidence — passed to analyst.<br><span class="badge badge-yellow">FLAG</span> Finding needs human review — evidence is partial.<br><span class="badge badge-red">BLOCK</span> Finding is hallucinated — blocked automatically.<br><br>The agent learns from blocked findings via the <strong style="color:var(--text)">Self-Improvement Loop</strong>, adjusting its behavior to reduce hallucinations over time. All evaluations are traced through Arize Phoenix for observability.</p></div></div>
        </div>
'''

# Insert before the settings page close and modal
insert_before = '    </div>\n</div>\n\n<!-- Modal -->'
if insert_before in content:
    content = content.replace(insert_before, pages_html + '\n    </div>\n</div>\n\n<!-- Modal -->')
    print("Added Cases, Traces, and Accuracy pages")
else:
    print("ERROR: Could not find insertion point")

# Add loadCasesPage and loadTracesPage functions
old_js_end = "// Initialize Lucide icons"
if old_js_end not in content:
    old_js_end = "function viewCase"

# Add page load handlers to the showPage function
old_showpage = '''if(p==="settings")loadSettings()'''
new_showpage = '''if(p==="settings")loadSettings();if(p==="cases")loadCasesPage();if(p==="traces")loadTracesPage();if(p==="accuracy")loadAccuracyPage()'''

if old_showpage in content:
    content = content.replace(old_showpage, new_showpage)
    print("Updated showPage with new page handlers")
else:
    print("ERROR: Could not find showPage handler")

# Add the new page load functions before viewCase
old_viewcase = "function viewCase"
new_functions = '''async function loadCasesPage(){try{const r=await fetch("/api/cases");const d=await r.json();const p=document.getElementById("full-cases-list");if(!d.cases||!d.cases.length){p.innerHTML=\'<div class="empty"><i data-lucide="folder-open"></i><h3>No cases yet</h3><p>Start an investigation from the Dashboard</p></div>\';lucide.createIcons();return}p.innerHTML=d.cases.map(c=>`<div class="feed-item" style="cursor:pointer" onclick="viewCase(\'${c.case_id}\')"><div class="feed-dot ${c.status===\'complete\'?\'finding\':\'tool\'}"><i data-lucide="${c.status===\'complete\'?\'check-circle\':\'loader\'}"></i></div><div class="feed-text"><div class="feed-title">${c.case_id}</div><div class="feed-detail">Status: ${c.status} | ${c.findings_count||0} findings | ${c.blocked_count||0} blocked | ${Math.round(c.duration||0)}s</div></div><span class="badge badge-${c.status===\'complete\'?\'green\':c.status===\'running\'?\'blue\':\'yellow\'}">${c.status}</span></div>`).join("");lucide.createIcons()}catch(e){}}
async function loadTracesPage(){try{const r=await fetch("/api/status");const s=await r.json();document.getElementById("trace-mode").textContent=s.phoenix?.mode||"unknown";document.getElementById("trace-project").textContent=s.phoenix?.project||"aegis-ir";lucide.createIcons()}catch(e){}}
async function loadAccuracyPage(){try{const r=await fetch("/api/metrics");const m=await r.json();document.getElementById("acc-approved").textContent=m.findings||0;document.getElementById("acc-flagged").textContent="0";document.getElementById("acc-blocked").textContent=m.blocked||0;lucide.createIcons()}catch(e){}}
function viewCase'''

if old_viewcase in content:
    content = content.replace(old_viewcase, new_functions)
    print("Added page load functions")
else:
    print("ERROR: Could not find viewCase")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("\\nDone! All pages added.")
