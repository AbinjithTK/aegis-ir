"""Patch the dashboard to add SIFT settings and improve case persistence."""

path = r'F:\Abin\Sifthack\aegis-ir\src\sift_defender\web\templates\dashboard.html'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add SIFT section to settings (insert after Gemini section)
old_settings_end = '''<button class="btn btn-primary btn-sm" onclick="saveSetting(\'gemini\')">Save</button></div></div>`;'''
new_settings_end = '''<button class="btn btn-primary btn-sm" onclick="saveSetting(\'gemini\')">Save</button></div></div><div class="card" style="margin-top:12px"><div class="card-head"><span>SIFT Forensic Tools</span><i data-lucide="hard-drive"></i></div><div class="card-body"><div class="two-col"><div class="form-group"><label class="form-label">Mode</label><select class="form-input" id="s-sm"><option value="local">Local (Linux/WSL)</option><option value="cloud">Cloud (gRPC VM)</option></select></div><div class="form-group"><label class="form-label">Evidence Path</label><input class="form-input" id="s-se" value="${s.sift?.evidence_path||"/mnt/evidence"}"></div></div><div class="form-group"><label class="form-label">Cloud Endpoint (gRPC)</label><input class="form-input" id="s-sep" placeholder="10.x.x.x:50051" value="${s.sift?.endpoint||""}"><div class="form-hint">Required for Cloud mode. IP:port of SIFT VM with forensic tools.</div></div><button class="btn btn-primary btn-sm" onclick="saveSetting(\'sift\')">Save</button></div></div>`;'''

if old_settings_end in content:
    content = content.replace(old_settings_end, new_settings_end)
    print("Added SIFT section to settings")
else:
    print("ERROR: Could not find settings insertion point")

# 2. Add SIFT mode select initialization after gemini model
old_select_init = '''document.getElementById("s-gm").value=s.gemini?.model||"gemini-2.5-flash";lucide.createIcons()'''
new_select_init = '''document.getElementById("s-gm").value=s.gemini?.model||"gemini-2.5-flash";if(document.getElementById("s-sm"))document.getElementById("s-sm").value=s.sift?.mode||"local";lucide.createIcons()'''

if old_select_init in content:
    content = content.replace(old_select_init, new_select_init)
    print("Added SIFT mode initialization")
else:
    print("ERROR: Could not find select init point")

# 3. Add SIFT to saveSetting function
old_save = '''if(sec==="gemini")payload.gemini={project:document.getElementById("s-gp").value,location:document.getElementById("s-gr").value,model:document.getElementById("s-gm").value,use_vertex:true};'''
new_save = '''if(sec==="gemini")payload.gemini={project:document.getElementById("s-gp").value,location:document.getElementById("s-gr").value,model:document.getElementById("s-gm").value,use_vertex:true};if(sec==="sift")payload.sift={mode:document.getElementById("s-sm").value,evidence_path:document.getElementById("s-se").value,endpoint:document.getElementById("s-sep").value};'''

if old_save in content:
    content = content.replace(old_save, new_save)
    print("Added SIFT to save function")
else:
    print("ERROR: Could not find save function point")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Done! Dashboard patched.")
