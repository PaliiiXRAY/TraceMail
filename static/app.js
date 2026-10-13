// TraceMail Client Application
let map = null;
let markersLayer = null;
let polylineLayer = null;
let currentAnalysisData = null;

// Initialize when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    initMap();
    setupDropzone();
    setupExportPdf();
});

// Initialize Leaflet Map
function initMap() {
    map = L.map('map', {
        center: [30.0, 10.0],
        zoom: 2,
        minZoom: 1.5,
        maxZoom: 10,
        attributionControl: false
    });

    // Dark Matter CartoDB Basemap (Free & Cyber-Themed)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);

    markersLayer = L.layerGroup().addTo(map);
    polylineLayer = L.layerGroup().addTo(map);
}

// Drag & Drop Handling
function setupDropzone() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');

    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('border-cyan-400', 'bg-cyan-500/10');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('border-cyan-400', 'bg-cyan-500/10');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('border-cyan-400', 'bg-cyan-500/10');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
}

function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        document.getElementById('rawInput').value = e.target.result;
        runAnalysis();
    };
    reader.readAsText(file);
}

function clearInput() {
    document.getElementById('rawInput').value = '';
    document.getElementById('fileInput').value = '';
}

// Load Pre-seeded Sample
async function loadSample(sampleId) {
    try {
        const resp = await fetch(`/api/sample/${sampleId}`);
        const data = await resp.json();
        if (data.raw_email) {
            document.getElementById('rawInput').value = data.raw_email;
            runAnalysis();
        }
    } catch (err) {
        console.error("Failed to load sample:", err);
    }
}

// Execute Analysis API Call
async function runAnalysis() {
    const rawContent = document.getElementById('rawInput').value.trim();
    if (!rawContent) {
        alert("Please paste an email header or select one of the preloaded demo samples!");
        return;
    }

    const analyzeBtn = document.getElementById('analyzeBtn');
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Analyzing Forensic Stream...`;
    lucide.createIcons();

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_email: rawContent })
        });

        const result = await resp.json();
        if (result.error) {
            alert("Analysis Error: " + result.error);
            return;
        }

        currentAnalysisData = result;
        renderResults(result);
    } catch (err) {
        alert("Server connection failed: " + err.message);
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = `<i data-lucide="search-code" class="w-4 h-4"></i> Execute Forensic Analysis`;
        lucide.createIcons();
    }
}

// Render Results on Dashboard
function renderResults(data) {
    const { email, auth, domain, hops, threat } = data;

    // Show Export PDF Button
    const exportBtn = document.getElementById('exportPdfBtn');
    exportBtn.classList.remove('hidden');
    exportBtn.classList.add('flex');

    // 1. Threat Verdict & Gauge
    const verdictBadge = document.getElementById('verdictBadge');
    verdictBadge.textContent = threat.verdict;
    verdictBadge.className = "px-3 py-1 rounded-full text-xs font-bold font-mono uppercase border " + 
        (threat.badge_color === 'red' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
         threat.badge_color === 'orange' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
         threat.badge_color === 'yellow' ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' :
         'bg-emerald-500/20 text-emerald-400 border-emerald-500/40');

    const scoreDisplay = document.getElementById('threatScoreDisplay');
    scoreDisplay.textContent = `${threat.threat_score}%`;
    scoreDisplay.className = "text-2xl font-black font-mono " +
        (threat.threat_score >= 75 ? 'text-red-400' :
         threat.threat_score >= 50 ? 'text-orange-400' :
         threat.threat_score >= 25 ? 'text-amber-400' : 'text-emerald-400');

    document.getElementById('threatSeverityLabel').textContent = 
        threat.threat_score >= 75 ? 'Critical Malicious Threat' :
        threat.threat_score >= 50 ? 'High Risk Impersonation' :
        threat.threat_score >= 25 ? 'Medium Suspicion' : 'Verified Authentic';

    // 2. Protocol Badges
    setBadge('spfStatusBadge', auth.spf);
    setBadge('dkimStatusBadge', auth.dkim);
    setBadge('dmarcStatusBadge', auth.dmarc);

    // 3. Metadata Header Info
    document.getElementById('metaSubject').textContent = email.subject || "(No Subject)";
    document.getElementById('metaFrom').textContent = `${email.display_name} <${email.envelope_sender}>`;
    document.getElementById('metaDomain').textContent = domain.domain || "(Not Found)";
    document.getElementById('metaAction').textContent = threat.recommended_action;

    const lookalikeBadge = document.getElementById('metaLookalikeBadge');
    if (domain.is_lookalike) {
        lookalikeBadge.classList.remove('hidden');
        lookalikeBadge.textContent = `LOOKALIKE: mimics ${domain.matched_target}`;
    } else {
        lookalikeBadge.classList.add('hidden');
    }

    // 4. Update Map & Relay Chain
    renderMapAndHops(hops);

    // 5. Threat Signals List
    const signalsContainer = document.getElementById('signalsContainer');
    signalsContainer.innerHTML = '';
    if (threat.signals.length === 0) {
        signalsContainer.innerHTML = `<div class="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-lg text-xs text-emerald-300">
            No anomalous indicators detected. Email conforms to trusted sender parameters.
        </div>`;
    } else {
        threat.signals.forEach(sig => {
            const colorClass = sig.type === 'CRITICAL' ? 'border-red-500/40 bg-red-950/30 text-red-200' :
                               sig.type === 'HIGH' ? 'border-orange-500/40 bg-orange-950/30 text-orange-200' :
                               'border-amber-500/40 bg-amber-950/30 text-amber-200';
            const badgeBg = sig.type === 'CRITICAL' ? 'bg-red-500 text-white' :
                            sig.type === 'HIGH' ? 'bg-orange-500 text-white' : 'bg-amber-500 text-black';
            
            const card = document.createElement('div');
            card.className = `p-3 rounded-lg border ${colorClass} text-xs space-y-1`;
            card.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="font-bold flex items-center gap-1.5">${sig.title}</span>
                    <span class="text-[10px] font-mono px-1.5 py-0.5 rounded ${badgeBg}">${sig.type}</span>
                </div>
                <p class="text-slate-300 text-[11px]">${sig.detail}</p>
            `;
            signalsContainer.appendChild(card);
        });
    }

    // 6. Indicators of Compromise (IoCs)
    const iocsBody = document.getElementById('iocsTableBody');
    iocsBody.innerHTML = '';
    if (threat.iocs.length === 0) {
        iocsBody.innerHTML = `<tr><td colspan="3" class="py-4 text-center text-slate-500 italic">No threat indicators to export.</td></tr>`;
    } else {
        threat.iocs.forEach(ioc => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-900/60 transition-colors";
            tr.innerHTML = `
                <td class="py-2 px-2.5 font-bold text-red-400">${ioc.type}</td>
                <td class="py-2 px-2.5 font-mono text-cyan-300 select-all">${ioc.value}</td>
                <td class="py-2 px-2.5 text-slate-400">${ioc.context}</td>
            `;
            iocsBody.appendChild(tr);
        });
    }

    lucide.createIcons();
}

function setBadge(elementId, status) {
    const el = document.getElementById(elementId);
    el.textContent = (status || 'NONE').toUpperCase();
    if (status === 'pass') {
        el.className = "text-lg font-bold font-mono text-emerald-400";
    } else if (status === 'fail') {
        el.className = "text-lg font-bold font-mono text-red-400";
    } else {
        el.className = "text-lg font-bold font-mono text-amber-400";
    }
}

// Render Map and Polyline Trajectory
function renderMapAndHops(hops) {
    markersLayer.clearLayers();
    polylineLayer.clearLayers();

    const tbody = document.getElementById('hopsTableBody');
    tbody.innerHTML = '';

    if (!hops || hops.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500 italic">No valid public IP hops found in Received headers.</td></tr>`;
        return;
    }

    const latlngs = [];

    hops.forEach((hop, idx) => {
        const isOrigin = (idx === 0);
        const isDest = (idx === hops.length - 1);
        const pinClass = isOrigin ? 'pin-origin' : (isDest ? 'pin-dest' : 'pin-relay');
        const roleBadge = isOrigin ? 'text-red-400' : (isDest ? 'text-emerald-400' : 'text-amber-400');

        // Table Row
        const tr = document.createElement('tr');
        tr.className = "hover:bg-slate-900/80 transition-colors";
        tr.innerHTML = `
            <td class="py-2.5 px-3 font-bold text-slate-200">#${hop.hop_number}</td>
            <td class="py-2.5 px-3 ${roleBadge} font-medium">${hop.role}</td>
            <td class="py-2.5 px-3 text-cyan-400 select-all">${hop.ip}</td>
            <td class="py-2.5 px-3 text-slate-300">${hop.city}, ${hop.country}</td>
            <td class="py-2.5 px-3 text-slate-400 truncate max-w-xs" title="${hop.org}">${hop.asn} (${hop.org})</td>
            <td class="py-2.5 px-3">
                ${hop.is_suspicious_host ? '<span class="px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 text-[10px]">SUSPICIOUS HOST</span>' :
                                           '<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">STANDARD</span>'}
            </td>
        `;
        tbody.appendChild(tr);

        // Map Marker
        if (hop.lat && hop.lon) {
            const point = [hop.lat, hop.lon];
            latlngs.push(point);

            const customIcon = L.divIcon({
                className: `cyber-pin ${pinClass}`,
                html: `<span>${hop.hop_number}</span>`,
                iconSize: [26, 26],
                iconAnchor: [13, 13]
            });

            const marker = L.marker(point, { icon: customIcon }).addTo(markersLayer);
            marker.bindPopup(`
                <div class="text-xs space-y-1 font-mono">
                    <div class="font-bold text-cyan-400 border-b border-slate-700 pb-1">HOP #${hop.hop_number}: ${hop.role}</div>
                    <div><strong>IP:</strong> ${hop.ip}</div>
                    <div><strong>Location:</strong> ${hop.city}, ${hop.country}</div>
                    <div><strong>ASN/Host:</strong> ${hop.asn} - ${hop.org}</div>
                </div>
            `);
        }
    });

    // Draw animated trajectory polyline
    if (latlngs.length > 1) {
        const polyline = L.polyline(latlngs, {
            color: '#ef4444',
            weight: 3,
            opacity: 0.85,
            className: 'animated-relay-line'
        }).addTo(polylineLayer);

        map.fitBounds(polyline.getBounds(), { padding: [50, 50], maxZoom: 5 });
    } else if (latlngs.length === 1) {
        map.setView(latlngs[0], 4);
    }
}

// 1-Click PDF Incident Forensic Report Generator
function setupExportPdf() {
    document.getElementById('exportPdfBtn').addEventListener('click', () => {
        if (!currentAnalysisData) return;
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        const data = currentAnalysisData;
        const threat = data.threat;

        // Title & Header Banner
        doc.setFillColor(11, 16, 26);
        doc.rect(0, 0, 210, 32, 'F');

        doc.setTextColor(6, 182, 212);
        doc.setFontSize(18);
        doc.setFont('helvetica', 'bold');
        doc.text("TRACEMAIL | FORENSIC INCIDENT DOSSIER", 14, 15);

        doc.setFontSize(9);
        doc.setTextColor(148, 163, 184);
        doc.text("TraceMail: AI-Powered Email Threat Detection & Infrastructure Forensic Platform", 14, 23);
        doc.text(`Generated: ${new Date().toUTCString()}`, 14, 28);

        // Threat Verdict Summary Box
        doc.setFontSize(12);
        doc.setTextColor(15, 23, 42);
        doc.text("1. Executive Threat Verdict", 14, 42);

        const verdictColor = threat.threat_score >= 75 ? [239, 68, 68] :
                             threat.threat_score >= 50 ? [249, 115, 22] : [16, 185, 129];
        doc.setFillColor(verdictColor[0], verdictColor[1], verdictColor[2]);
        doc.roundedRect(14, 46, 182, 14, 2, 2, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(11);
        doc.text(`VERDICT: ${threat.verdict} (Risk Score: ${threat.threat_score}/100)`, 20, 55);

        // Metadata Table
        doc.autoTable({
            startY: 64,
            head: [['Field', 'Observed Value']],
            body: [
                ['Subject', data.email.subject],
                ['Sender Envelope', data.email.envelope_sender],
                ['Display Name', data.email.display_name],
                ['Sender Domain', data.domain.domain],
                ['SPF / DKIM / DMARC', `${data.auth.spf.toUpperCase()} / ${data.auth.dkim.toUpperCase()} / ${data.auth.dmarc.toUpperCase()}`],
                ['Recommended SOC Action', threat.recommended_action]
            ],
            theme: 'grid',
            headStyles: { fillColor: [30, 41, 59] },
            styles: { fontSize: 8 }
        });

        // Hop By Hop Relay Trace Table
        doc.setFontSize(12);
        doc.setTextColor(15, 23, 42);
        doc.text("2. Forensic Infrastructure Relay Chain (SMTP Trace)", 14, doc.lastAutoTable.finalY + 12);

        const hopRows = data.hops.map(h => [
            `#${h.hop_number}`,
            h.role,
            h.ip,
            `${h.city}, ${h.country}`,
            `${h.asn} - ${h.org}`,
            h.is_suspicious_host ? 'SUSPICIOUS' : 'NORMAL'
        ]);

        doc.autoTable({
            startY: doc.lastAutoTable.finalY + 16,
            head: [['Hop', 'Role', 'IP Address', 'Location', 'Autonomous System & Host', 'Status']],
            body: hopRows.length > 0 ? hopRows : [['-', 'No external hops', '-', '-', '-', '-']],
            theme: 'grid',
            headStyles: { fillColor: [6, 182, 212] },
            styles: { fontSize: 8 }
        });

        // Indicators of Compromise (IoCs)
        doc.setFontSize(12);
        doc.setTextColor(15, 23, 42);
        doc.text("3. Indicators of Compromise (IoCs for Firewall / SOC Blocking)", 14, doc.lastAutoTable.finalY + 12);

        const iocRows = threat.iocs.map(i => [i.type, i.value, i.context]);
        doc.autoTable({
            startY: doc.lastAutoTable.finalY + 16,
            head: [['Indicator Type', 'Threat Artifact', 'Context / Trigger']],
            body: iocRows.length > 0 ? iocRows : [['CLEAN', 'No malicious IoCs identified', 'All indicators normal']],
            theme: 'striped',
            headStyles: { fillColor: [239, 68, 68] },
            styles: { fontSize: 8 }
        });

        doc.save(`TraceMail_Forensic_Dossier_${Date.now()}.pdf`);
    });
}
