"""
Embedded Dark-Theme SOC Web Dashboard for SUDO SPANDR ESG.
Single-page reactive cybersecurity interface with real-time SSE stream, Quarantine manager, and Attack Simulator.
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SUDO SPANDR ESG - Enterprise Mail Flow Gateway</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#00f0ff', 600: '#00c8d7' },
            cyber: { 900: '#0a0d14', 800: '#101522', 700: '#182032', 600: '#222d44' }
          }
        }
      }
    }
  </script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
    .font-mono { font-family: 'JetBrains Mono', monospace; }
    .glow-cyan { box-shadow: 0 0 20px rgba(0, 240, 255, 0.25); }
    .glow-red { box-shadow: 0 0 20px rgba(239, 68, 68, 0.25); }
    .custom-scroll::-webkit-scrollbar { width: 6px; height: 6px; }
    .custom-scroll::-webkit-scrollbar-track { background: #0a0d14; }
    .custom-scroll::-webkit-scrollbar-thumb { background: #222d44; border-radius: 4px; }
  </style>
</head>
<body class="bg-[#07090e] text-slate-200 min-h-screen custom-scroll flex flex-col">

  <!-- Top Navigation Header -->
  <header class="border-b border-cyber-600 bg-cyber-900/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
    <div class="flex items-center gap-3.5">
      <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/30">
        <i class="fa-solid fa-shield-halved text-black text-xl"></i>
      </div>
      <div>
        <div class="flex items-center gap-2.5">
          <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
            SUDO SPANDR <span class="text-cyan-400 font-mono text-xs px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800">ESG v4.0</span>
          </h1>
          <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> LIVE INTERCEPTOR
          </span>
        </div>
        <p class="text-xs text-slate-400">Enterprise Mail Flow Gateway & Milter Daemon &bull; SIH #26106</p>
      </div>
    </div>

    <!-- Active Sockets & Sinks -->
    <div class="flex items-center gap-3">
      <div class="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400 bg-cyber-800 px-3 py-1.5 rounded-lg border border-cyber-600">
        <span><i class="fa-solid fa-network-wired text-cyan-400"></i> SMTP: <b class="text-white">:10025</b></span>
        <span class="text-slate-600">|</span>
        <span><i class="fa-solid fa-bolt text-amber-400"></i> Milter: <b class="text-white">:8893</b></span>
        <span class="text-slate-600">|</span>
        <span><i class="fa-solid fa-server text-indigo-400"></i> API: <b class="text-white">:8002</b></span>
      </div>
      <button onclick="refreshData()" class="px-3 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs font-semibold rounded-lg border border-cyber-600 transition flex items-center gap-1.5">
        <i class="fa-solid fa-rotate text-cyan-400"></i> Refresh
      </button>
    </div>
  </header>

  <!-- Metrics Counter Strip -->
  <section class="p-6 max-w-7xl mx-auto w-full grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
    <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-4 flex flex-col justify-between">
      <div class="flex items-center justify-between text-slate-400 text-xs">
        <span>TOTAL SCANNED</span>
        <i class="fa-solid fa-envelope-open-text text-cyan-400"></i>
      </div>
      <div class="mt-2 text-2xl font-bold font-mono text-white" id="stat-total">0</div>
      <div class="text-[11px] text-slate-500 mt-1">Inbound mail stream</div>
    </div>

    <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-4 flex flex-col justify-between">
      <div class="flex items-center justify-between text-slate-400 text-xs">
        <span>CLEAN DELIVERED</span>
        <i class="fa-solid fa-circle-check text-emerald-400"></i>
      </div>
      <div class="mt-2 text-2xl font-bold font-mono text-emerald-400" id="stat-clean">0</div>
      <div class="text-[11px] text-emerald-500/80 mt-1">Score &lt; 40 (Continue)</div>
    </div>

    <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-4 flex flex-col justify-between">
      <div class="flex items-center justify-between text-slate-400 text-xs">
        <span>SUSPICIOUS TAGGED</span>
        <i class="fa-solid fa-triangle-exclamation text-amber-400"></i>
      </div>
      <div class="mt-2 text-2xl font-bold font-mono text-amber-400" id="stat-tagged">0</div>
      <div class="text-[11px] text-amber-500/80 mt-1">40 &le; Score &lt; 75 (Tag)</div>
    </div>

    <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-4 flex flex-col justify-between">
      <div class="flex items-center justify-between text-slate-400 text-xs">
        <span>QUARANTINED VAULT</span>
        <i class="fa-solid fa-box-archive text-purple-400"></i>
      </div>
      <div class="mt-2 text-2xl font-bold font-mono text-purple-400" id="stat-quarantine">0</div>
      <div class="text-[11px] text-purple-500/80 mt-1">BSA Sec 63 Sealed</div>
    </div>

    <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-4 flex flex-col justify-between">
      <div class="flex items-center justify-between text-slate-400 text-xs">
        <span>HARD REJECTED</span>
        <i class="fa-solid fa-ban text-rose-500"></i>
      </div>
      <div class="mt-2 text-2xl font-bold font-mono text-rose-500" id="stat-rejected">0</div>
      <div class="text-[11px] text-rose-500/80 mt-1">SMTP 550 Blocked</div>
    </div>

    <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-4 flex flex-col justify-between">
      <div class="flex items-center justify-between text-slate-400 text-xs">
        <span>AVG SCAN TIME</span>
        <i class="fa-solid fa-gauge-high text-cyan-400"></i>
      </div>
      <div class="mt-2 text-2xl font-bold font-mono text-cyan-400"><span id="stat-latency">0</span><span class="text-xs font-normal">ms</span></div>
      <div class="text-[11px] text-cyan-500/80 mt-1">Zero-delay pipeline</div>
    </div>
  </section>

  <!-- Navigation Tabs -->
  <div class="max-w-7xl mx-auto w-full px-6 mb-4">
    <div class="flex border-b border-cyber-600 gap-2">
      <button onclick="switchTab('stream')" id="tab-btn-stream" class="px-4 py-2.5 text-sm font-semibold border-b-2 border-cyan-400 text-cyan-400 flex items-center gap-2">
        <i class="fa-solid fa-tower-broadcast"></i> Live Interception Feed
      </button>
      <button onclick="switchTab('autopsy')" id="tab-btn-autopsy" class="px-4 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-white flex items-center gap-2">
        <i class="fa-solid fa-microscope text-cyan-400"></i> Forensic Autopsy Lab
      </button>
      <button onclick="switchTab('quarantine')" id="tab-btn-quarantine" class="px-4 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-white flex items-center gap-2">
        <i class="fa-solid fa-vault"></i> Evidence Quarantine Vault
      </button>
      <button onclick="switchTab('archive')" id="tab-btn-archive" class="px-4 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-white flex items-center gap-2">
        <i class="fa-solid fa-folder-tree text-cyan-400"></i> Intercepted Mail Archive
      </button>
      <button onclick="switchTab('simulator')" id="tab-btn-simulator" class="px-4 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-white flex items-center gap-2">
        <i class="fa-solid fa-vial-virus"></i> Attack &amp; Policy Simulator
      </button>
      <button onclick="switchTab('topology')" id="tab-btn-topology" class="px-4 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-white flex items-center gap-2">
        <i class="fa-solid fa-diagram-project"></i> Postfix &amp; Topology
      </button>

    </div>
  </div>

  <!-- Main Content Areas -->
  <main class="max-w-7xl mx-auto w-full px-6 flex-1 pb-10">

    <!-- TAB 1: LIVE INTERCEPTION STREAM -->
    <div id="tab-stream" class="space-y-4">
      <div class="bg-cyber-800 border border-cyber-600 rounded-xl overflow-hidden shadow-xl">
        <div class="p-4 border-b border-cyber-600 flex flex-wrap items-center justify-between gap-3 bg-cyber-900/60">
          <div>
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-satellite-dish text-cyan-400 animate-pulse"></i> Real-Time SMTP / Milter Inbound Stream
            </h3>
            <p class="text-xs text-slate-400">Live events captured directly from port 10025 (SMTP) & 8893 (Milter)</p>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-400">Stream Status:</span>
            <span class="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">CONNECTED</span>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-cyber-900/80 text-slate-400 uppercase font-mono text-[11px] border-b border-cyber-600">
              <tr>
                <th class="py-3 px-4">Case ID</th>
                <th class="py-3 px-4">Time</th>
                <th class="py-3 px-4">Sender &bull; Domain</th>
                <th class="py-3 px-4">Recipient</th>
                <th class="py-3 px-4">Threat Score</th>
                <th class="py-3 px-4">Category</th>
                <th class="py-3 px-4">Action</th>
                <th class="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody id="stream-tbody" class="divide-y divide-cyber-700/60 font-sans">
              <tr>
                <td colspan="8" class="py-8 text-center text-slate-500 font-mono">
                  <i class="fa-solid fa-radar fa-spin text-2xl text-cyan-500 mb-2 block"></i>
                  Waiting for incoming SMTP / Milter mail connections...
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 2: EVIDENCE QUARANTINE VAULT -->
    <div id="tab-quarantine" class="hidden space-y-4">
      <div class="bg-cyber-800 border border-cyber-600 rounded-xl overflow-hidden shadow-xl">
        <div class="p-4 border-b border-cyber-600 flex flex-wrap items-center justify-between gap-3 bg-cyber-900/60">
          <div>
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-lock text-purple-400"></i> Section 63 BSA 2023 Evidence Quarantine Vault
            </h3>
            <p class="text-xs text-slate-400">Cryptographically sealed EML storage with HMAC integrity verification</p>
          </div>
          <button onclick="loadQuarantineList()" class="px-3 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs font-semibold rounded-lg border border-cyber-600 transition flex items-center gap-1.5">
            <i class="fa-solid fa-arrows-rotate text-purple-400"></i> Refresh Vault
          </button>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-cyber-900/80 text-slate-400 uppercase font-mono text-[11px] border-b border-cyber-600">
              <tr>
                <th class="py-3 px-4">Case ID</th>
                <th class="py-3 px-4">Quarantined At</th>
                <th class="py-3 px-4">Sender</th>
                <th class="py-3 px-4">Subject</th>
                <th class="py-3 px-4">Threat Score</th>
                <th class="py-3 px-4">BSA Hash (SHA-256)</th>
                <th class="py-3 px-4">Status</th>
                <th class="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="quarantine-tbody" class="divide-y divide-cyber-700/60">
              <tr>
                <td colspan="8" class="py-8 text-center text-slate-500 font-mono">Loading quarantine vault records...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    <!-- TAB 2.5: CONTINUOUS INTERCEPTED MAIL ARCHIVE -->
    <div id="tab-archive" class="hidden space-y-4">
      <div class="bg-cyber-800 border border-cyber-600 rounded-xl overflow-hidden shadow-xl">
        <div class="p-4 border-b border-cyber-600 flex flex-wrap items-center justify-between gap-3 bg-cyber-900/60">
          <div>
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-folder-tree text-cyan-400"></i> Intercepted Inbound Email Vault Archive
            </h3>
            <p class="text-xs text-slate-400">Continuous forensic persistence of every incoming email (.eml + JSON report + summary)</p>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="triggerAnalystTestAlert()" class="px-3 py-1.5 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition">
              <i class="fa-solid fa-bell"></i> Test Analyst Alert
            </button>
            <button onclick="loadArchiveList()" class="px-3 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs font-semibold rounded-lg border border-cyber-600 transition flex items-center gap-1.5">
              <i class="fa-solid fa-arrows-rotate text-cyan-400"></i> Refresh Archive
            </button>
          </div>
        </div>

        <div class="p-3 bg-cyber-900/70 border-b border-cyber-700/60 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-2">
          <div><i class="fa-solid fa-folder text-amber-400 mr-1"></i> Current Storage Vault: <code id="archive-vault-path" class="text-cyan-400 font-mono text-[11px]">Loading...</code></div>
          <div class="flex items-center gap-3">
            <span>Desktop Alert: <b class="text-emerald-400">ACTIVE</b></span>
            <span class="text-slate-600">|</span>
            <span>Alert Threshold: <b class="text-amber-400">&ge; 70% Threat Score</b></span>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-cyber-900/80 text-slate-400 uppercase font-mono text-[11px] border-b border-cyber-600">
              <tr>
                <th class="py-3 px-4">Case ID</th>
                <th class="py-3 px-4">Intercepted At</th>
                <th class="py-3 px-4">Sender</th>
                <th class="py-3 px-4">Subject</th>
                <th class="py-3 px-4">Threat Score</th>
                <th class="py-3 px-4">Verdict</th>
                <th class="py-3 px-4">Action</th>
                <th class="py-3 px-4 text-right">Forensic Files</th>
              </tr>
            </thead>
            <tbody id="archive-tbody" class="divide-y divide-cyber-700/60">
              <tr>
                <td colspan="8" class="py-8 text-center text-slate-500 font-mono">Loading archived email records...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: ATTACK & POLICY SIMULATOR -->
    <div id="tab-simulator" class="hidden grid grid-cols-1 lg:grid-cols-2 gap-6">

      <!-- Input Panel -->
      <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 shadow-xl space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-terminal text-cyan-400"></i> Inbound Message Simulator
          </h3>
          <span class="text-xs text-slate-400">Preset Scenarios:</span>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-3 gap-2">
          <button onclick="loadPreset('bec')" class="px-2.5 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs rounded border border-cyber-600 text-left truncate">
            💼 CEO Wire ($25.6M)
          </button>
          <button onclick="loadPreset('spoof')" class="px-2.5 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs rounded border border-cyber-600 text-left truncate">
            🏦 Bank of Baroda Spoof
          </button>
          <button onclick="loadPreset('quishing')" class="px-2.5 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs rounded border border-cyber-600 text-left truncate">
            📱 2FA Quishing QR
          </button>
          <button onclick="loadPreset('malware')" class="px-2.5 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs rounded border border-cyber-600 text-left truncate">
            💣 Double Ext .pdf.exe
          </button>
          <button onclick="loadPreset('clean')" class="px-2.5 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs rounded border border-cyber-600 text-left truncate">
            ✅ Clean Project Sync
          </button>
          <button onclick="loadPreset('phish')" class="px-2.5 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-xs rounded border border-cyber-600 text-left truncate">
            🎣 Credential Harvest
          </button>
        </div>

        <div class="space-y-3 pt-2">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Sender (MAIL FROM):</label>
            <input id="sim-sender" type="text" class="w-full bg-cyber-900 border border-cyber-600 rounded-lg px-3 py-2 text-xs font-mono text-white focus:border-cyan-400 focus:outline-none" value="attacker@b0b-security-update.in">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Recipient (RCPT TO):</label>
            <input id="sim-rcpt" type="text" class="w-full bg-cyber-900 border border-cyber-600 rounded-lg px-3 py-2 text-xs font-mono text-white focus:border-cyan-400 focus:outline-none" value="executive@company.com">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Subject:</label>
            <input id="sim-subject" type="text" class="w-full bg-cyber-900 border border-cyber-600 rounded-lg px-3 py-2 text-xs text-white focus:border-cyan-400 focus:outline-none" value="URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Email Body Content:</label>
            <textarea id="sim-body" rows="6" class="w-full bg-cyber-900 border border-cyber-600 rounded-lg p-3 text-xs font-mono text-slate-200 focus:border-cyan-400 focus:outline-none custom-scroll">Please wire $25.6M immediately to our external bank account. Strictly confidential, do not disclose to other team members. Sent from my iPhone in a private meeting.</textarea>
          </div>
        </div>

        <button onclick="runSimulation()" class="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-bold text-xs rounded-lg shadow-lg shadow-cyan-500/20 transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> EXECUTE ESG INTERCEPTION SIMULATION
        </button>
      </div>

      <!-- Result Panel -->
      <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 shadow-xl space-y-4 flex flex-col justify-between" id="sim-result-box">
        <div>
          <h3 class="text-sm font-bold text-white flex items-center gap-2 mb-3">
            <i class="fa-solid fa-chart-pie text-cyan-400"></i> ESG Interception &amp; Policy Verdict
          </h3>

          <div id="sim-output-empty" class="text-center py-16 text-slate-500 font-mono text-xs">
            <i class="fa-solid fa-shield-cat text-3xl mb-2 block text-slate-600"></i>
            Click "Execute ESG Interception" to inspect simulation results.
          </div>

          <div id="sim-output-content" class="hidden space-y-4">
            <div class="grid grid-cols-2 gap-3">
              <div class="bg-cyber-900 p-3 rounded-lg border border-cyber-600">
                <span class="text-[10px] text-slate-400 block uppercase font-mono">Threat Score</span>
                <span id="sim-score" class="text-2xl font-bold font-mono">--</span>
              </div>
              <div class="bg-cyber-900 p-3 rounded-lg border border-cyber-600">
                <span class="text-[10px] text-slate-400 block uppercase font-mono">Policy Action</span>
                <span id="sim-policy" class="text-sm font-bold font-mono">--</span>
              </div>
            </div>

            <div class="bg-cyber-900 p-3 rounded-lg border border-cyber-600">
              <span class="text-[10px] text-slate-400 block uppercase font-mono mb-1">SMTP Protocol Reply</span>
              <div id="sim-reply" class="text-xs font-mono text-slate-300">--</div>
            </div>

            <div class="bg-cyber-900 p-3 rounded-lg border border-cyber-600">
              <span class="text-[10px] text-slate-400 block uppercase font-mono mb-1.5">Triggered Threat Rules</span>
              <div id="sim-findings" class="space-y-1.5 text-xs">--</div>
            </div>

            <div class="bg-cyber-900 p-3 rounded-lg border border-cyber-600">
              <span class="text-[10px] text-slate-400 block uppercase font-mono mb-1">Forensic Headers Injected</span>
              <pre id="sim-headers" class="text-[11px] font-mono text-cyan-300 overflow-x-auto custom-scroll max-h-32">--</pre>
            </div>
          </div>
        </div>

        <div class="text-[11px] text-slate-500 border-t border-cyber-600 pt-3 flex items-center justify-between">
          <span>Evaluator: <b id="sim-evaluator" class="text-slate-300">--</b></span>
          <span>Latency: <b id="sim-latency" class="text-cyan-400">--</b></span>
        </div>
      </div>
    </div>

    <!-- TAB 4: TOPOLOGY & POSTFIX INTEGRATION -->
    <div id="tab-topology" class="hidden space-y-6">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 space-y-4">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-server text-cyan-400"></i> Postfix `main.cf` Milter Setup
          </h3>
          <p class="text-xs text-slate-400">Add the following directives to your Postfix mail server configuration:</p>
          <pre class="bg-cyber-900 border border-cyber-600 rounded-lg p-4 font-mono text-xs text-cyan-300 overflow-x-auto custom-scroll"># /etc/postfix/main.cf - SUDO SPANDR ESG Milter
smtpd_milters = inet:127.0.0.1:8893
non_smtpd_milters = inet:127.0.0.1:8893
milter_default_action = accept
milter_protocol = 6
milter_connect_macros = j {daemon_name} v
milter_helo_macros = {tls_version} {cipher} {cipher_bits}
milter_mail_macros = i {auth_type} {auth_authen}</pre>
        </div>

        <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 space-y-4">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-arrow-right-arrow-left text-indigo-400"></i> SMTP Proxy Relaying Setup
          </h3>
          <p class="text-xs text-slate-400">Configure your Edge Router / MX record to point to SUDO SPANDR ESG:</p>
          <pre class="bg-cyber-900 border border-cyber-600 rounded-lg p-4 font-mono text-xs text-indigo-300 overflow-x-auto custom-scroll"># Inbound MX points to SUDO SPANDR ESG (Port 10025 or 25)
# ESG inspects traffic -> relays clean/tagged mail to internal MTA:
CS_GW_SMTP_LISTEN_PORT=10025
CS_GW_SMTP_RELAY_HOST=127.0.0.1
    <!-- TAB: FORENSIC AUTOPSY LAB -->
    <div id="tab-autopsy" class="hidden space-y-6">
      <!-- Search and Inspect Bar -->
      <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-lg">
            <i class="fa-solid fa-microscope"></i>
          </div>
          <div>
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              DEEP FORENSIC AUTOPSY LABORATORY &bull; SECTION 63 BSA
            </h3>
            <p class="text-xs text-slate-400">Surgical email postmortem: Multi-Hop Relay reconstruction, MITRE ATT&CK, Cognitive NLP, and CDR Disarm</p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-1 max-w-md">
          <input id="autopsy-search-input" type="text" placeholder="Enter Case ID (e.g. SPANDR-ESG-47B61E9FCE)" class="flex-1 bg-cyber-900 border border-cyber-600 rounded-lg px-3 py-2 text-xs font-mono text-white focus:border-cyan-400 focus:outline-none">
          <button onclick="fetchAutopsyDossier()" class="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-bold text-xs rounded-lg transition flex items-center gap-1.5">
            <i class="fa-solid fa-dna"></i> Dissect
          </button>
        </div>
      </div>

      <!-- Autopsy Dossier Container -->
      <div id="autopsy-dossier-empty" class="bg-cyber-800 border border-cyber-600 rounded-xl p-16 text-center text-slate-500 font-mono text-xs">
        <i class="fa-solid fa-user-secret text-4xl mb-3 block text-slate-600"></i>
        Enter a Case ID from the Live Feed or Quarantine Vault to launch a surgical forensic autopsy.
      </div>

      <div id="autopsy-dossier-view" class="hidden space-y-6">
        <!-- Top Metadata & Section 63 Ledger Card -->
        <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 shadow-xl grid grid-cols-1 md:grid-cols-4 gap-4">
          <div class="bg-cyber-900 p-3.5 rounded-lg border border-cyber-700">
            <span class="text-[10px] text-slate-400 block uppercase font-mono">Dossier Reference</span>
            <span id="auto-ref" class="text-sm font-bold font-mono text-cyan-400 truncate block">--</span>
          </div>
          <div class="bg-cyber-900 p-3.5 rounded-lg border border-cyber-700">
            <span class="text-[10px] text-slate-400 block uppercase font-mono">Originating Node IP</span>
            <span id="auto-ip" class="text-sm font-bold font-mono text-rose-400 block">--</span>
          </div>
          <div class="bg-cyber-900 p-3.5 rounded-lg border border-cyber-700">
            <span class="text-[10px] text-slate-400 block uppercase font-mono">Origin Location</span>
            <span id="auto-loc" class="text-sm font-bold text-white block">--</span>
          </div>
          <div class="bg-cyber-900 p-3.5 rounded-lg border border-cyber-700 flex flex-col justify-center">
            <button onclick="viewCurrentBsaCert()" class="w-full py-1.5 bg-emerald-950 text-emerald-400 border border-emerald-800 hover:bg-emerald-900 rounded font-semibold text-xs transition flex items-center justify-center gap-1.5">
              <i class="fa-solid fa-stamp"></i> BSA Sec 63 Court Cert
            </button>
          </div>
        </div>

        <!-- 1. Multi-Hop Relay Reconstruction -->
        <div class="bg-cyber-800 border border-cyber-600 rounded-xl overflow-hidden shadow-xl">
          <div class="p-4 border-b border-cyber-600 bg-cyber-900/60 flex items-center justify-between">
            <h4 class="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2 font-mono">
              <i class="fa-solid fa-route"></i> 1. Multi-Hop Transport Relay Reconstruction &amp; Delta-T Timing
            </h4>
            <span class="text-[11px] text-slate-400">Reverse Chronological &bull; RFC 5322 Inbound Path</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
              <thead class="bg-cyber-900/80 text-slate-400 uppercase font-mono text-[11px] border-b border-cyber-600">
                <tr>
                  <th class="py-2.5 px-4">Hop</th>
                  <th class="py-2.5 px-4">From Host</th>
                  <th class="py-2.5 px-4">By Host</th>
                  <th class="py-2.5 px-4">Relay IP</th>
                  <th class="py-2.5 px-4">Protocol &amp; TLS</th>
                  <th class="py-2.5 px-4">Hop Delay (&Delta;t)</th>
                  <th class="py-2.5 px-4">Threat Intel</th>
                </tr>
              </thead>
              <tbody id="auto-hops-tbody" class="divide-y divide-cyber-700/60 font-mono text-[11px]">
                <!-- Hops rendered here -->
              </tbody>
            </table>
          </div>
        </div>

        <!-- 2. MITRE ATT&CK Matrix & Cognitive Linguistics (2 Columns) -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- MITRE Matrix -->
          <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 shadow-xl space-y-3">
            <h4 class="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-2 font-mono border-b border-cyber-600 pb-2">
              <i class="fa-solid fa-shield-virus"></i> 2. MITRE ATT&amp;CK Enterprise Matrix Mapping
            </h4>
            <div id="auto-mitre-container" class="space-y-2 max-h-80 overflow-y-auto custom-scroll pr-1">
              <!-- MITRE Cards rendered here -->
            </div>
          </div>

          <!-- Cognitive Linguistics -->
          <div class="bg-cyber-800 border border-cyber-600 rounded-xl p-5 shadow-xl space-y-3">
            <h4 class="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2 font-mono border-b border-cyber-600 pb-2">
              <i class="fa-solid fa-brain"></i> 3. Cognitive Linguistics &amp; Social Engineering Dissection
            </h4>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div class="bg-cyber-900 p-2.5 rounded border border-cyber-700 text-center">
                <span class="text-[10px] text-slate-400 block uppercase font-mono">Fear / Penalty</span>
                <span id="cog-fear" class="text-lg font-bold font-mono text-rose-400">0</span>
              </div>
              <div class="bg-cyber-900 p-2.5 rounded border border-cyber-700 text-center">
                <span class="text-[10px] text-slate-400 block uppercase font-mono">Financial Urgency</span>
                <span id="cog-fin" class="text-lg font-bold font-mono text-amber-400">0</span>
              </div>
              <div class="bg-cyber-900 p-2.5 rounded border border-cyber-700 text-center">
                <span class="text-[10px] text-slate-400 block uppercase font-mono">Authority</span>
                <span id="cog-auth" class="text-lg font-bold font-mono text-cyan-400">0</span>
              </div>
              <div class="bg-cyber-900 p-2.5 rounded border border-cyber-700 text-center">
                <span class="text-[10px] text-slate-400 block uppercase font-mono">Psych Index</span>
                <span id="cog-comp" class="text-lg font-bold font-mono text-purple-400">0%</span>
              </div>
            </div>
            <div class="text-xs font-semibold text-slate-300 pt-1">Detected Cognitive Levers &amp; Linguistic Anchors:</div>
            <div id="auto-cog-cues" class="space-y-1.5 max-h-48 overflow-y-auto custom-scroll">
              <!-- Cognitive triggers rendered here -->
            </div>
          </div>
        </div>

        <!-- 3. CDR Disarm & Reconstruction -->
        <div class="bg-cyber-800 border border-cyber-600 rounded-xl overflow-hidden shadow-xl">
          <div class="p-4 border-b border-cyber-600 bg-cyber-900/60 flex items-center justify-between">
            <h4 class="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2 font-mono">
              <i class="fa-solid fa-wand-magic-sparkles"></i> 4. Content Disarm &amp; Reconstruction (CDR) Engine
            </h4>
            <span class="text-[11px] text-slate-400">Neutralization of Active Payloads &amp; Double Extensions</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
              <thead class="bg-cyber-900/80 text-slate-400 uppercase font-mono text-[11px] border-b border-cyber-600">
                <tr>
                  <th class="py-2.5 px-4">Original File</th>
                  <th class="py-2.5 px-4">Sanitized File</th>
                  <th class="py-2.5 px-4">CDR Action</th>
                  <th class="py-2.5 px-4">Neutralized Threats</th>
                  <th class="py-2.5 px-4">Safety Status</th>
                </tr>
              </thead>
              <tbody id="auto-cdr-tbody" class="divide-y divide-cyber-700/60 font-mono text-[11px]">
                <!-- CDR reports rendered here -->
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

  </main>

  <!-- Section 63 BSA Modal -->
  <div id="bsa-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
    <div class="bg-cyber-800 border border-cyber-600 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
      <div class="flex items-center justify-between border-b border-cyber-600 pb-3">
        <h3 class="text-sm font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-stamp text-amber-400"></i> SECTION 63 BSA 2023 FORENSIC CERTIFICATE
        </h3>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div id="bsa-modal-content" class="text-xs font-mono text-slate-300 bg-cyber-900 p-4 rounded-xl max-h-96 overflow-y-auto custom-scroll border border-cyber-600">
        Loading certificate...
      </div>
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="closeModal()" class="px-4 py-2 bg-cyber-700 text-xs font-semibold rounded-lg">Close</button>
      </div>
    </div>
  </div>

  <script>
    // Tab Switching
    function switchTab(tabId) {
      ['stream', 'autopsy', 'quarantine', 'archive', 'simulator', 'topology'].forEach(t => {
        const pane = document.getElementById(`tab-${t}`);
        const btn = document.getElementById(`tab-btn-${t}`);
        if (pane) pane.classList.add('hidden');
        if (btn) btn.className = 'px-4 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-white flex items-center gap-2';
      });
      const activePane = document.getElementById(`tab-${tabId}`);
      const activeBtn = document.getElementById(`tab-btn-${tabId}`);
      if (activePane) activePane.classList.remove('hidden');
      if (activeBtn) activeBtn.className = 'px-4 py-2.5 text-sm font-semibold border-b-2 border-cyan-400 text-cyan-400 flex items-center gap-2';

      if (tabId === 'quarantine') loadQuarantineList();
      if (tabId === 'archive') loadArchiveList();
    }


    let currentAutopsyDossier = null;

    function openAutopsy(caseId) {
      switchTab('autopsy');
      document.getElementById('autopsy-search-input').value = caseId;
      fetchAutopsyDossier(caseId);
    }

    async function fetchAutopsyDossier(targetCaseId) {
      const caseId = targetCaseId || document.getElementById('autopsy-search-input').value.trim();
      if (!caseId) {
        alert("Please enter a valid Case ID (e.g. SPANDR-ESG-...)");
        return;
      }

      try {
        const res = await fetch(`/api/v1/autopsy/${caseId}`);
        if (!res.ok) {
          alert(`Autopsy report for ${caseId} could not be retrieved. Ensure case is in vault.`);
          return;
        }
        const data = await res.json();
        const dossier = data.autopsy_dossier;
        currentAutopsyDossier = dossier;
        renderAutopsyDossier(dossier);
      } catch (e) {
        alert("Autopsy fetch error: " + e);
      }
    }

    function renderAutopsyDossier(d) {
      document.getElementById('autopsy-dossier-empty').classList.add('hidden');
      document.getElementById('autopsy-dossier-view').classList.remove('hidden');

      document.getElementById('auto-ref').innerText = d.autopsy_id;
      document.getElementById('auto-ip').innerText = d.originating_ip;
      document.getElementById('auto-loc').innerText = d.origin_country;

      // 1. Relay Hops
      const hopsTbody = document.getElementById('auto-hops-tbody');
      hopsTbody.innerHTML = (d.hop_sequence || []).map(h => {
        const isTor = h.is_tor_or_vpn;
        const tag = h.threat_intel ? h.threat_intel.type : 'Standard Relay';
        return `
          <tr class="hover:bg-cyber-700/40 transition">
            <td class="py-2.5 px-4 font-bold text-cyan-400">#${h.hop_number} ${h.is_originating ? '<span class="text-[10px] text-rose-400">(ORIGIN)</span>' : ''}</td>
            <td class="py-2.5 px-4 text-white">${escapeHtml(h.from_host)}</td>
            <td class="py-2.5 px-4 text-slate-400">${escapeHtml(h.by_host)}</td>
            <td class="py-2.5 px-4 ${isTor ? 'text-rose-400 font-bold' : 'text-amber-300'}">${h.ip_address}</td>
            <td class="py-2.5 px-4 text-slate-300">${escapeHtml(h.protocol)} &bull; ${escapeHtml(h.tls_version)}</td>
            <td class="py-2.5 px-4 text-right">${h.delta_seconds}s</td>
            <td class="py-2.5 px-4">
              <span class="px-2 py-0.5 rounded text-[10px] font-mono ${isTor ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse' : 'bg-cyber-700 text-slate-300'}">${tag}</span>
            </td>
          </tr>
        `;
      }).join('');

      // 2. MITRE Matrix
      const mitreBox = document.getElementById('auto-mitre-container');
      mitreBox.innerHTML = (d.mitre_attack_matrix || []).map(m => `
        <div class="p-3 bg-cyber-900 rounded-lg border border-cyber-700">
          <div class="flex items-center justify-between">
            <span class="text-xs font-mono font-bold text-rose-400">${m.id} &bull; ${escapeHtml(m.technique)}</span>
            <span class="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 uppercase font-mono">${escapeHtml(m.tactic)}</span>
          </div>
          <div class="text-[11px] text-slate-300 mt-1 font-semibold">${escapeHtml(m.subtechnique || '')}</div>
          <div class="text-[11px] text-slate-400 mt-1">${escapeHtml(m.description || '')}</div>
          ${m.finding_title ? `<div class="text-[10px] text-amber-400 font-mono mt-1.5 bg-amber-950/40 p-1 rounded border border-amber-900/50">Evidence: ${escapeHtml(m.finding_title)}</div>` : ''}
        </div>
      `).join('');

      // 3. Cognitive Linguistics
      const cog = d.cognitive_profile || {};
      document.getElementById('cog-fear').innerText = cog.fear_coercion_score || 0;
      document.getElementById('cog-fin').innerText = cog.financial_urgency_score || 0;
      document.getElementById('cog-auth').innerText = cog.authority_pressure_score || 0;
      document.getElementById('cog-comp').innerText = `${cog.composite_psychological_index || 0}%`;

      const cuesBox = document.getElementById('auto-cog-cues');
      cuesBox.innerHTML = (cog.cognitive_cues_observed || []).map(c => `
        <div class="p-2 bg-cyber-900 rounded border border-cyber-700 flex items-center justify-between text-xs">
          <div>
            <span class="text-amber-400 font-mono font-semibold">[${escapeHtml(c.lever)}]</span>
            <span class="text-slate-300 ml-1">"${escapeHtml(c.trigger)}"</span>
          </div>
          <span class="text-[10px] text-slate-400">${escapeHtml(c.explanation)}</span>
        </div>
      `).join('') || '<div class="text-slate-500 text-xs font-mono">No aggressive cognitive triggers detected.</div>';

      // 4. CDR Disarm Reports
      const cdrTbody = document.getElementById('auto-cdr-tbody');
      if (!d.cdr_disarm_reports || d.cdr_disarm_reports.length === 0) {
        cdrTbody.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-slate-500 font-mono">No weaponized attachments detected in this email.</td></tr>`;
      } else {
        cdrTbody.innerHTML = d.cdr_disarm_reports.map(r => `
          <tr class="hover:bg-cyber-700/40 transition">
            <td class="py-2.5 px-4 text-rose-300 font-bold">${escapeHtml(r.original_filename)}</td>
            <td class="py-2.5 px-4 text-emerald-400 font-bold">${escapeHtml(r.sanitized_filename)}</td>
            <td class="py-2.5 px-4">
              <span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono">${r.disarm_action}</span>
            </td>
            <td class="py-2.5 px-4 text-slate-300 text-[10px]">${(r.threats_neutralized || []).join(', ')}</td>
            <td class="py-2.5 px-4">
              <span class="px-2 py-0.5 rounded text-[10px] ${r.safe_to_render ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'} font-mono">${r.safe_to_render ? 'SAFE TO RENDER' : 'TRAPPED IN ENCLAVE'}</span>
            </td>
          </tr>
        `).join('');
      }
    }

    function viewCurrentBsaCert() {
      if (!currentAutopsyDossier) return;
      document.getElementById('bsa-modal').classList.remove('hidden');
      const box = document.getElementById('bsa-modal-content');
      box.innerText = JSON.stringify(currentAutopsyDossier.bsa_section_63_certificate, null, 2);
    }

    // Refresh Data
    async function refreshData() {
      try {
        const res = await fetch('/api/v1/stats');
        if (res.ok) {
          const d = await res.json();
          document.getElementById('stat-total').innerText = d.total_scanned;
          document.getElementById('stat-clean').innerText = d.clean_count;
          document.getElementById('stat-tagged').innerText = d.tagged_count;
          document.getElementById('stat-quarantine').innerText = d.quarantined_count;
          document.getElementById('stat-rejected').innerText = d.rejected_count;
          document.getElementById('stat-latency').innerText = d.avg_latency_ms;

          renderStreamRows(d.recent_events);
        }
      } catch (e) {
        console.error("Stats refresh error:", e);
      }
    }

    function renderStreamRows(events) {
      const tbody = document.getElementById('stream-tbody');
      if (!events || events.length === 0) return;

      tbody.innerHTML = events.map(e => {
        let badgeColor = e.threat_score >= 75 ? 'bg-rose-950 text-rose-400 border-rose-800' :
                         e.threat_score >= 40 ? 'bg-amber-950 text-amber-400 border-amber-800' :
                         'bg-emerald-950 text-emerald-400 border-emerald-800';

        let actionBadge = e.policy_action === 'REJECT' ? 'bg-red-900/50 text-red-300' :
                          e.policy_action === 'QUARANTINE' ? 'bg-purple-900/50 text-purple-300' :
                          e.policy_action === 'TAG_SUBJECT' ? 'bg-amber-900/50 text-amber-300' :
                          'bg-emerald-900/50 text-emerald-300';

        return `
          <tr class="hover:bg-cyber-700/40 transition">
            <td class="py-3 px-4 font-mono text-cyan-400 font-semibold cursor-pointer hover:underline" onclick="openAutopsy('${e.case_id}')">${e.case_id}</td>
            <td class="py-3 px-4 text-slate-400">${new Date(e.timestamp).toLocaleTimeString()}</td>
            <td class="py-3 px-4">
              <div class="font-medium text-white">${escapeHtml(e.sender)}</div>
              <div class="text-[11px] text-slate-400 truncate max-w-xs">${escapeHtml(e.subject || 'No Subject')}</div>
            </td>
            <td class="py-3 px-4 text-slate-300 truncate max-w-xs">${escapeHtml(e.recipient)}</td>
            <td class="py-3 px-4">
              <span class="px-2 py-0.5 rounded font-mono font-bold border ${badgeColor}">${e.threat_score}%</span>
            </td>
            <td class="py-3 px-4 text-slate-300">${escapeHtml(e.category)}</td>
            <td class="py-3 px-4">
              <span class="px-2 py-0.5 rounded font-mono text-[11px] ${actionBadge}">${e.policy_action}</span>
            </td>
            <td class="py-3 px-4 text-right">
              <button onclick="openAutopsy('${e.case_id}')" class="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-400 border border-cyan-800 rounded text-xs font-semibold">
                <i class="fa-solid fa-microscope mr-1"></i> Autopsy
              </button>
            </td>
          </tr>
        `;
      }).join('');
    }

    // Load Quarantine Records
    async function loadQuarantineList() {
      const tbody = document.getElementById('quarantine-tbody');
      try {
        const res = await fetch('/api/v1/quarantine');
        if (res.ok) {
          const list = await res.json();
          if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="py-8 text-center text-slate-500 font-mono">Quarantine vault is currently empty. No intercepted threats stored yet.</td></tr>`;
            return;
          }
          tbody.innerHTML = list.map(c => `
            <tr class="hover:bg-cyber-700/40 transition">
              <td class="py-3 px-4 font-mono text-purple-400 font-bold cursor-pointer hover:underline" onclick="openAutopsy('${c.case_id}')">${c.case_id}</td>
              <td class="py-3 px-4 text-slate-400">${new Date(c.timestamp).toLocaleString()}</td>
              <td class="py-3 px-4 text-slate-200 font-medium">${escapeHtml(c.sender)}</td>
              <td class="py-3 px-4 text-slate-300 truncate max-w-xs">${escapeHtml(c.subject)}</td>
              <td class="py-3 px-4 font-mono text-rose-400 font-bold">${c.threat_score}%</td>
              <td class="py-3 px-4 font-mono text-[10px] text-cyan-400">${(c.sha256_hash || '').substring(0, 16)}...</td>
              <td class="py-3 px-4">
                <span class="px-2 py-0.5 rounded text-[11px] font-mono ${c.status === 'RELEASED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-purple-950 text-purple-300 border border-purple-800'}">${c.status}</span>
              </td>
              <td class="py-3 px-4 text-right space-x-1.5">
                <button onclick="openAutopsy('${c.case_id}')" title="Forensic Autopsy Lab" class="px-2 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 rounded text-cyan-400 text-xs"><i class="fa-solid fa-microscope"></i></button>
                <button onclick="viewBsaCert('${c.case_id}')" title="Section 63 BSA Certificate" class="px-2 py-1 bg-cyber-700 hover:bg-cyber-600 rounded text-amber-400 text-xs"><i class="fa-solid fa-stamp"></i></button>
                <a href="/api/v1/quarantine/${c.case_id}/raw" download="${c.case_id}.eml" title="Download Raw EML" class="inline-block px-2 py-1 bg-cyber-700 hover:bg-cyber-600 rounded text-cyan-400 text-xs"><i class="fa-solid fa-download"></i></a>
                <button onclick="releaseQuarantine('${c.case_id}')" title="Release to Mailbox" class="px-2 py-1 bg-emerald-900/70 hover:bg-emerald-800 rounded text-emerald-300 text-xs"><i class="fa-solid fa-paper-plane"></i></button>
              </td>
            </tr>
          `).join('');
        }
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="py-8 text-center text-rose-400 font-mono">Failed to load quarantine records: ${e}</td></tr>`;
      }
    }

    // Load Continuous Intercepted Archive Records
    async function loadArchiveList() {
      const tbody = document.getElementById('archive-tbody');
      try {
        const res = await fetch('/api/v1/archive?limit=100');
        if (res.ok) {
          const data = await res.json();
          const pathEl = document.getElementById('archive-vault-path');
          if (pathEl) pathEl.innerText = data.archive_dir || 'Default';

          const list = data.cases || [];
          if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="py-8 text-center text-slate-500 font-mono">Archive vault is empty. All processed incoming emails will automatically appear here.</td></tr>`;
            return;
          }
          tbody.innerHTML = list.map(c => {
            let badgeColor = c.threat_score >= 75 ? 'bg-rose-950 text-rose-400 border-rose-800' :
                             c.threat_score >= 40 ? 'bg-amber-950 text-amber-400 border-amber-800' :
                             'bg-emerald-950 text-emerald-400 border-emerald-800';

            return `
              <tr class="hover:bg-cyber-700/40 transition">
                <td class="py-3 px-4 font-mono text-cyan-400 font-bold cursor-pointer hover:underline" onclick="openAutopsy('${c.case_id}')">${c.case_id}</td>
                <td class="py-3 px-4 text-slate-400">${new Date(c.timestamp).toLocaleString()}</td>
                <td class="py-3 px-4 text-slate-200 font-medium">${escapeHtml(c.sender)}</td>
                <td class="py-3 px-4 text-slate-300 truncate max-w-xs">${escapeHtml(c.subject || '(No Subject)')}</td>
                <td class="py-3 px-4">
                  <span class="px-2 py-0.5 rounded font-mono font-bold border ${badgeColor}">${c.threat_score}%</span>
                </td>
                <td class="py-3 px-4 text-slate-300">${escapeHtml(c.verdict)}</td>
                <td class="py-3 px-4">
                  <span class="px-2 py-0.5 rounded font-mono text-[11px] bg-cyber-700 text-slate-300">${c.policy_action}</span>
                </td>
                <td class="py-3 px-4 text-right space-x-1.5">
                  <button onclick="openAutopsy('${c.case_id}')" title="Forensic Autopsy" class="px-2 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 rounded text-cyan-400 text-xs"><i class="fa-solid fa-microscope"></i></button>
                  <a href="/api/v1/archive/${c.case_id}/summary" target="_blank" title="View Summary Report" class="inline-block px-2 py-1 bg-cyber-700 hover:bg-cyber-600 rounded text-amber-400 text-xs"><i class="fa-solid fa-file-lines"></i></a>
                </td>
              </tr>
            `;
          }).join('');
        }
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="py-8 text-center text-rose-400 font-mono">Failed to load archive: ${e}</td></tr>`;
      }
    }

    async function triggerAnalystTestAlert() {
      try {
        const res = await fetch('/api/v1/analyst/test-alert', { method: 'POST' });
        if (res.ok) {
          const d = await res.json();
          alert(`Test alert dispatched!\nDesktop: ${d.channel_dispatch_results.desktop ? 'Triggered' : 'N/A'}\nCase: ${d.case_id}`);
        } else {
          alert("Failed to trigger test alert.");
        }
      } catch (e) {
        alert("Error triggering alert: " + e);
      }
    }

    async function viewBsaCert(caseId) {

      document.getElementById('bsa-modal').classList.remove('hidden');
      const box = document.getElementById('bsa-modal-content');
      box.innerText = "Loading cryptographic verification...";
      try {
        const res = await fetch(`/api/v1/quarantine/${caseId}/bsa-certificate`);
        if (res.ok) {
          const cert = await res.json();
          box.innerText = JSON.stringify(cert, null, 2);
        }
      } catch (e) {
        box.innerText = "Error loading certificate: " + e;
      }
    }

    function closeModal() {
      document.getElementById('bsa-modal').classList.add('hidden');
    }

    async function releaseQuarantine(caseId) {
      if (!confirm(`Are you sure you want to release ${caseId} to the recipient?`)) return;
      try {
        const res = await fetch(`/api/v1/quarantine/${caseId}/release`, { method: 'POST' });
        const data = await res.json();
        alert(data.message || data.status);
        loadQuarantineList();
      } catch (e) {
        alert("Release failed: " + e);
      }
    }

    // Presets for Attack Simulator
    const PRESETS = {
      bec: {
        sender: "executive@b0b-finance-update.in",
        rcpt: "finance@company.com",
        subject: "URGENT: Confidential Wire Transfer Needed Immediately ($25.6M)",
        body: "Please wire $25.6M immediately to our external bank account. Strictly confidential, do not disclose to other team members. Sent from my iPhone in a private meeting."
      },
      spoof: {
        sender: "alerts@b0b-bank-security.in",
        rcpt: "customer@company.com",
        subject: "Action Required: Bank of Baroda Account Suspension Notice",
        body: "Your Bank of Baroda corporate account has been flagged. Verify your login credentials within 2 hours at http://192.168.10.45/login/bob-auth to prevent account freeze."
      },
      quishing: {
        sender: "it-support@cloud-tenant-update.com",
        rcpt: "employee@company.com",
        subject: "Microsoft Authenticator 2FA Security Update Required",
        body: "Scan the below QR code with your mobile device immediately to update your Microsoft Authenticator MFA token before access is revoked.\n\n[Embedded QR Code Image: 2FA Authentication Sync]"
      },
      malware: {
        sender: "billing@vendor-express.net",
        rcpt: "accounting@company.com",
        subject: "Overdue Invoice #INV-2026-9901 - Payment Pending",
        body: "Please find attached the signed receipt and overdue invoice. Remit payment today.\n\nAttachment: Invoice_Overdue_Statement.pdf.exe"
      },
      clean: {
        sender: "colleague@partner-company.com",
        rcpt: "team@company.com",
        subject: "Project Sprint Roadmap & Meeting Minutes",
        body: "Hi team, thanks for attending today's sprint sync. The minutes and action items have been documented on the internal wiki. See you at tomorrow's standup."
      },
      phish: {
        sender: "security@office365-verify-portal.net",
        rcpt: "user@company.com",
        subject: "Password Expiry Notice: Verify Your Password",
        body: "Your corporate password expires in 24 hours. Sign in to http://secure.portal.verify-user.office365-verify-portal.net/login to retain your active credentials."
      }
    };

    function loadPreset(key) {
      const p = PRESETS[key];
      if (!p) return;
      document.getElementById('sim-sender').value = p.sender;
      document.getElementById('sim-rcpt').value = p.rcpt;
      document.getElementById('sim-subject').value = p.subject;
      document.getElementById('sim-body').value = p.body;
    }

    async function runSimulation() {
      const sender = document.getElementById('sim-sender').value;
      const recipient = document.getElementById('sim-rcpt').value;
      const subject = document.getElementById('sim-subject').value;
      const body = document.getElementById('sim-body').value;

      try {
        const res = await fetch('/api/v1/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sender, recipient, subject, body })
        });

        if (res.ok) {
          const d = await res.json();
          document.getElementById('sim-output-empty').classList.add('hidden');
          document.getElementById('sim-output-content').classList.remove('hidden');

          const scoreEl = document.getElementById('sim-score');
          scoreEl.innerText = `${d.threat_score}% (${d.verdict})`;
          scoreEl.className = `text-2xl font-bold font-mono ${d.threat_score >= 75 ? 'text-rose-400' : d.threat_score >= 40 ? 'text-amber-400' : 'text-emerald-400'}`;

          const policyEl = document.getElementById('sim-policy');
          policyEl.innerText = `${d.policy_action} [${d.postfix_code}]`;
          policyEl.className = `text-sm font-bold font-mono ${d.policy_action === 'REJECT' ? 'text-rose-400' : d.policy_action === 'QUARANTINE' ? 'text-purple-400' : d.policy_action === 'TAG_SUBJECT' ? 'text-amber-400' : 'text-emerald-400'}`;

          document.getElementById('sim-reply').innerText = d.smtp_reply;

          const findingsEl = document.getElementById('sim-findings');
          if (d.findings && d.findings.length > 0) {
            findingsEl.innerHTML = d.findings.map(f => `
              <div class="p-2 rounded bg-cyber-800 border border-cyber-700">
                <div class="font-semibold text-white flex items-center justify-between">
                  <span>${escapeHtml(f.title)}</span>
                  <span class="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 font-mono">+${f.score_impact} pts</span>
                </div>
                <div class="text-slate-400 text-[11px] mt-0.5">${escapeHtml(f.description)}</div>
              </div>
            `).join('');
          } else {
            findingsEl.innerHTML = `<span class="text-emerald-400">No malicious signals or threat rules triggered.</span>`;
          }

          document.getElementById('sim-headers').innerText = Object.entries(d.headers_to_add || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
          document.getElementById('sim-evaluator').innerText = d.evaluated_by;
          document.getElementById('sim-latency').innerText = `${d.scan_time_ms}ms`;

          // Refresh stats
          refreshData();
        }
      } catch (e) {
        alert("Simulation error: " + e);
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Connect Server-Sent Events (SSE) for Real-Time Streaming
    function connectSSE() {
      try {
        const es = new EventSource('/api/v1/live-feed');
        es.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data);
            refreshData();
          } catch (err) {}
        };
      } catch (err) {}
    }

    // Initial Load
    window.addEventListener('DOMContentLoaded', () => {
      refreshData();
      connectSSE();
      setInterval(refreshData, 5000);
    });
  </script>
</body>
</html>
"""
