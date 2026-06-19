from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from src.app.config import settings
from src.app.db.session import engine, Base
from src.app.api.endpoints import environment, simulations, validation, stream

# Create DB Tables on Startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Modular Routers under api/v1 prefix
app.include_router(environment.router, prefix="/api/v1")
app.include_router(simulations.router, prefix="/api/v1")
app.include_router(validation.router, prefix="/api/v1")
app.include_router(stream.router, prefix="/api/v1")

# --- INTEGRATED WEB INTERFACE ---

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SOCForge | Telemetry & Cyber Range Control</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-main: #0B0F19;
                --bg-glass: rgba(17, 24, 39, 0.7);
                --border-glass: rgba(255, 255, 255, 0.08);
                --glow-cyan: #00F0FF;
                --glow-purple: #9D00FF;
                --glow-green: #39FF14;
                --text-primary: #F3F4F6;
                --text-muted: #9CA3AF;
            }
            body {
                background: var(--bg-main);
                color: var(--text-primary);
                font-family: 'Outfit', sans-serif;
                margin: 0;
                padding: 0;
                min-height: 100vh;
                background-image: radial-gradient(circle at 10% 20%, rgba(90, 0, 255, 0.15) 0%, transparent 40%),
                                  radial-gradient(circle at 90% 80%, rgba(0, 240, 255, 0.12) 0%, transparent 40%);
                background-attachment: fixed;
            }
            header {
                backdrop-filter: blur(12px);
                background: var(--bg-glass);
                border-bottom: 1px solid var(--border-glass);
                padding: 20px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: sticky;
                top: 0;
                z-index: 100;
            }
            header h1 {
                margin: 0;
                font-size: 28px;
                font-weight: 800;
                letter-spacing: 1.5px;
                background: linear-gradient(90deg, var(--glow-cyan), var(--glow-purple));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                text-shadow: 0 0 20px rgba(0, 240, 255, 0.2);
            }
            .nav-badge {
                border: 1px solid var(--glow-cyan);
                box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
                padding: 6px 14px;
                border-radius: 20px;
                font-size: 13px;
                font-family: 'JetBrains Mono', monospace;
                color: var(--glow-cyan);
            }
            .container {
                max-width: 1400px;
                margin: 30px auto;
                padding: 0 20px;
                display: grid;
                grid-template-columns: 1fr 2fr;
                gap: 25px;
            }
            .card {
                background: var(--bg-glass);
                backdrop-filter: blur(8px);
                border: 1px solid var(--border-glass);
                border-radius: 16px;
                padding: 24px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                transition: transform 0.3s ease, border-color 0.3s ease;
            }
            .card:hover {
                border-color: rgba(0, 240, 255, 0.2);
            }
            h2 {
                font-size: 20px;
                margin-top: 0;
                margin-bottom: 20px;
                border-left: 4px solid var(--glow-purple);
                padding-left: 10px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                font-size: 13px;
                color: var(--text-muted);
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            select, input {
                width: 100%;
                background: rgba(0,0,0,0.5);
                border: 1px solid var(--border-glass);
                border-radius: 8px;
                padding: 12px;
                color: white;
                font-family: inherit;
                box-sizing: border-box;
                font-size: 14px;
                outline: none;
                transition: border-color 0.2s ease;
            }
            select:focus, input:focus {
                border-color: var(--glow-cyan);
            }
            .btn {
                width: 100%;
                background: linear-gradient(90deg, var(--glow-cyan), var(--glow-purple));
                color: white;
                font-weight: 600;
                padding: 14px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                box-shadow: 0 0 15px rgba(157, 0, 255, 0.3);
                transition: opacity 0.2s ease, transform 0.1s ease;
            }
            .btn:hover {
                opacity: 0.9;
                transform: translateY(-1px);
            }
            /* Console Output */
            .console-panel {
                grid-column: span 2;
                background: rgba(5, 7, 12, 0.95);
                border: 1px solid var(--border-glass);
                border-radius: 12px;
                padding: 18px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                height: 350px;
                overflow-y: auto;
                color: var(--text-primary);
                box-shadow: inset 0 0 20px rgba(0,0,0,0.8);
            }
            .console-line {
                margin-bottom: 6px;
                border-bottom: 1px solid rgba(255,255,255,0.02);
                padding-bottom: 4px;
            }
            .c-tag {
                color: var(--glow-cyan);
                font-weight: bold;
            }
            .c-threat {
                color: #FF2E2E;
                font-weight: bold;
            }
            /* Graph & Alerts Panel */
            .right-column {
                display: flex;
                flex-direction: column;
                gap: 25px;
            }
            .graph-canvas {
                border: 1px solid var(--border-glass);
                background: rgba(0,0,0,0.3);
                border-radius: 12px;
                height: 250px;
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
                overflow: hidden;
            }
            .node {
                width: 80px;
                height: 40px;
                border-radius: 6px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 11px;
                font-weight: bold;
                text-align: center;
                position: absolute;
                border: 1px solid rgba(255,255,255,0.2);
            }
            .node.attacker { background: #FF2E2E; border-color: red; }
            .node.victim { background: #00F0FF; border-color: cyan; color: black; }
            .node.dc { background: #9D00FF; border-color: purple; }
            /* Alerts Table */
            .alert-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            .alert-table th, .alert-table td {
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid var(--border-glass);
                font-size: 13px;
            }
            .alert-table th { color: var(--text-muted); }
            .badge-critical { color: #FF2E2E; font-weight: bold; }
            .badge-high { color: orange; font-weight: bold; }
            .badge-medium { color: yellow; font-weight: bold; }
        </style>
    </head>
    <body>
        <header>
            <h1>SOCForge</h1>
            <div class="nav-badge">Telemetry Control Center v1.0.0</div>
        </header>

        <div class="container">
            <!-- Configuration Panel -->
            <div class="card">
                <h2>Cyber Range Builder</h2>
                <div class="form-group">
                    <label>Corporate Target Environment</label>
                    <input type="text" id="company_name" value="FinanceCorp">
                </div>
                <div class="form-group">
                    <label>Environment Size</label>
                    <select id="company_size">
                        <option value="small">Small (10 Hosts)</option>
                        <option value="medium" selected>Medium (30 Hosts)</option>
                        <option value="large">Large (120 Hosts)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Attack Scenario / Threat Profile</label>
                    <select id="scenario">
                        <option value="APT Campaign">APT29 (Cozy Bear Campaign)</option>
                        <option value="Ransomware">LockBit Ransomware (Mass File Lock)</option>
                        <option value="Kerberoasting">Kerberoasting (Active Directory SPN abuse)</option>
                        <option value="DCSync">DCSync (Domain Replication Dump)</option>
                        <option value="MFA Fatigue">MFA Fatigue (Push Bombing / Identity Bypass)</option>
                        <option value="Cloud Breach">AWS Cloud Breach (Access Key Compromise)</option>
                        <option value="Kubernetes Abuse">Kubernetes Container Escape & Crypto Mining</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Output Telemetry Format</label>
                    <select id="format">
                        <option value="json">Standard JSON</option>
                        <option value="edr">CrowdStrike / Defender EDR Event Stream</option>
                        <option value="syslog">Syslog RFC5424</option>
                        <option value="ndjson">NDJSON Logs</option>
                    </select>
                </div>
                <button class="btn" onclick="startSimulation()">Compile & Launch Range</button>
            </div>

            <!-- Graph and Alert Area -->
            <div class="right-column">
                <!-- Attack Path Visualizer -->
                <div class="card">
                    <h2>Attack Graph Progression</h2>
                    <div class="graph-canvas" id="graph_canvas">
                        <div style="color: var(--text-muted);">No active attack path. Compile a range to render nodes.</div>
                    </div>
                </div>

                <!-- Live Alarm Feed -->
                <div class="card">
                    <h2>Live Alerts (Triage Room)</h2>
                    <div style="max-height: 200px; overflow-y: auto;">
                        <table class="alert-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Host</th>
                                    <th>Rule Name</th>
                                    <th>Tactic</th>
                                </tr>
                            </thead>
                            <tbody id="alerts_body">
                                <tr><td colspan="4" style="color: var(--text-muted); text-align: center;">Waiting for telemetry...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Terminal Output -->
            <div class="console-panel" id="console_output">
                [+] System ready. Exposes REST/WebSocket API endpoints on port 8000.
                [+] Waiting for range simulation activation...
            </div>
        </div>

        <script>
            async function fnStartCompany() {
                const name = document.getElementById("company_name").value;
                const size = document.getElementById("company_size").value;
                const res = await fetch(`/api/v1/companies?name=${name}&size=${size}`, {method: 'POST'});
                return await res.json();
            }

            async function startSimulation() {
                const consoleDiv = document.getElementById("console_output");
                consoleDiv.innerHTML = "[*] Bootstrapping company topology...\\n";
                
                const comp = await fnStartCompany();
                consoleDiv.innerHTML += `[+] Company Created! Domain: ${comp.domain}, Hosts: ${comp.total_hosts}\\n`;
                
                const scenario = document.getElementById("scenario").value;
                const format = document.getElementById("format").value;
                
                consoleDiv.innerHTML += `[*] Launching simulation scenario: ${scenario} (${format} logs)...\\n`;
                
                const res = await fetch(`/api/v1/simulations/generate?company_id=${comp.company_id}&scenario=${scenario}&format=${format}`, {method: 'POST'});
                const data = await res.json();
                
                consoleDiv.innerHTML += `[+] Telemetry generated successfully!\\n`;
                consoleDiv.innerHTML += `[+] Dataset Signature: ${data.sha256_signature}\\n`;
                
                // Print Logs snippet
                const logs = data.data;
                const snippet = Array.isArray(logs) ? logs.slice(0, 10) : logs.split("\\n").slice(0, 10);
                
                consoleDiv.innerHTML += `\\n--- TELEMETRY OUTSTREAM SNIPPET ---\\n`;
                snippet.forEach(s => {
                    const str = typeof s === 'string' ? s : JSON.stringify(s);
                    consoleDiv.innerHTML += `<div class="console-line">${str}</div>`;
                });
                
                // Render Attack Graph Nodes
                const graphCanvas = document.getElementById("graph_canvas");
                graphCanvas.innerHTML = "";
                const nodes = data.attack_graph.nodes || [];
                nodes.forEach((n, idx) => {
                    const nodeDiv = document.createElement("div");
                    nodeDiv.className = `node ${n.type}`;
                    nodeDiv.style.left = `${50 + (idx * 110)}px`;
                    nodeDiv.style.top = `100px`;
                    nodeDiv.innerText = n.label;
                    graphCanvas.appendChild(nodeDiv);
                });
                
                // Populate Alerts
                const alertsBody = document.getElementById("alerts_body");
                alertsBody.innerHTML = "";
                if (data.alerts.length === 0) {
                    alertsBody.innerHTML = `<tr><td colspan="4" style="color: var(--text-muted); text-align: center;">No alarms triggered.</td></tr>`;
                } else {
                    data.alerts.forEach(a => {
                        const tr = document.createElement("tr");
                        const sevClass = `badge-${a.severity.toLowerCase()}`;
                        tr.innerHTML = `
                            <td class="${sevClass}">${a.severity}</td>
                            <td>${a.host || "Gateway"}</td>
                            <td>${a.rule_name}</td>
                            <td>${a.mitre_mapping.tactic}</td>
                        `;
                        alertsBody.appendChild(tr);
                    });
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
