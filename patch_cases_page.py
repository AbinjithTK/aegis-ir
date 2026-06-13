"""Fix the Cases page to properly display investigation history."""

path = r'F:\Abin\Sifthack\aegis-ir\src\sift_defender\web\templates\dashboard.html'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the loadCasesPage function - remove onclick that tries to reconnect WS to dead cases
old_fn = '''async function loadCasesPage(){try{const r=await fetch("/api/cases");const d=await r.json();const p=document.getElementById("full-cases-list");if(!d.cases||!d.cases.length){p.innerHTML=\'<div class="empty"><i data-lucide="folder-open"></i><h3>No cases yet</h3><p>Start an investigation from the Dashboard</p></div>\';lucide.createIcons();return}p.innerHTML=d.cases.map(c=>`<div class="feed-item" style="cursor:pointer" onclick="viewCase(\'${c.case_id}\')"><div class="feed-dot ${c.status===\'complete\'?\'finding\':\'tool\'}"><i data-lucide="${c.status===\'complete\'?\'check-circle\':\'loader\'}"></i></div><div class="feed-text"><div class="feed-title">${c.case_id}</div><div class="feed-detail">Status: ${c.status} | ${c.findings_count||0} findings | ${c.blocked_count||0} blocked | ${Math.round(c.duration||0)}s</div></div><span class="badge badge-${c.status===\'complete\'?\'green\':c.status===\'running\'?\'blue\':\'yellow\'}">${c.status}</span></div>`).join("");lucide.createIcons()}catch(e){}}'''

new_fn = '''async function loadCasesPage(){try{const r=await fetch("/api/cases");const d=await r.json();const p=document.getElementById("full-cases-list");if(!d.cases||!d.cases.length){p.innerHTML=\'<div class="empty"><i data-lucide="folder-open"></i><h3>No cases yet</h3><p>Start an investigation from the Dashboard</p></div>\';lucide.createIcons();return}p.innerHTML=d.cases.map(c=>{const duration=c.duration?Math.round(c.duration)+"s":"—";const statusCls=c.status==="complete"?"green":c.status==="running"?"blue":"yellow";return `<div class="feed-item"><div class="feed-dot ${c.status===\'complete\'?\'finding\':\'tool\'}"><i data-lucide="${c.status===\'complete\'?\'check-circle\':\'loader\'}"></i></div><div class="feed-text"><div class="feed-title">${c.case_id}</div><div class="feed-detail">${c.findings_count||0} findings &middot; ${c.blocked_count||0} blocked &middot; ${duration}</div></div><span class="badge badge-${statusCls}">${c.status}</span></div>`}).join("");lucide.createIcons()}catch(e){document.getElementById("full-cases-list").innerHTML=\'<div class="empty"><i data-lucide="alert-circle"></i><h3>Error loading cases</h3><p>Could not fetch case data</p></div>\';lucide.createIcons()}}'''

if old_fn in content:
    content = content.replace(old_fn, new_fn)
    print("Fixed loadCasesPage function")
else:
    print("ERROR: Could not find loadCasesPage function")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Done!")
