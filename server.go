package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
)

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Local HTTP Inspector</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, monospace;
            background: #1a1a1a;
            color: #ccc;
            line-height: 1.4;
            font-size: 12px;
        }
        .header {
            background: #252525;
            border-bottom: 1px solid #333;
            padding: 10px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 13px;
            font-weight: 500;
            color: #eee;
        }
        .header .info {
            font-size: 11px;
            color: #888;
        }
        .controls {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .controls a {
            color: #888;
            text-decoration: none;
            font-size: 11px;
        }
        .controls a:hover { color: #ccc; }
        #search {
            background: #1a1a1a;
            border: 1px solid #444;
            padding: 6px 10px;
            color: #ccc;
            font-family: inherit;
            font-size: 12px;
            width: 180px;
        }
        #search:focus { outline: none; border-color: #666; }
        #search::placeholder { color: #666; }
        .badge {
            background: #333;
            padding: 3px 8px;
            font-size: 11px;
            color: #888;
        }
        .container { padding: 16px; }
        .empty {
            text-align: center;
            padding: 40px 20px;
            color: #666;
        }
        .empty h2 { font-size: 13px; margin-bottom: 4px; color: #888; }
        .packet-list { display: flex; flex-direction: column; gap: 1px; background: #333; }
        .packet {
            background: #252525;
        }
        .packet-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            cursor: pointer;
        }
        .packet-header:hover { background: #2a2a2a; }
        .method {
            font-weight: 600;
            font-size: 11px;
            min-width: 50px;
        }
        .method.GET { color: #7c7; }
        .method.POST { color: #7af; }
        .method.PUT { color: #fa7; }
        .method.DELETE { color: #f77; }
        .method.PATCH { color: #c9f; }
        .method.TLS { color: #c97; }
        .method.RAW { color: #888; }
        .status {
            font-size: 11px;
        }
        .status.s2xx { color: #7c7; }
        .status.s3xx { color: #7af; }
        .status.s4xx { color: #fa7; }
        .status.s5xx { color: #f77; }
        .url {
            flex: 1;
            color: #ccc;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .timestamp {
            font-size: 11px;
            color: #666;
            white-space: nowrap;
        }
        .packet-details {
            display: none;
            border-top: 1px solid #333;
            padding: 12px;
            background: #1a1a1a;
        }
        .packet.expanded .packet-details { display: block; }
        .detail-section { margin-bottom: 12px; }
        .detail-section:last-child { margin-bottom: 0; }
        .detail-title {
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }
        .detail-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 6px;
        }
        .detail-header .detail-title { margin-bottom: 0; }
        .copy-btn {
            background: #2a2a2a;
            border: 1px solid #444;
            color: #888;
            font-family: inherit;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 2px 8px;
            cursor: pointer;
            flex-shrink: 0;
        }
        .copy-btn:hover { background: #333; color: #ccc; }
        .copy-btn.copied { color: #7c7; border-color: #7c7; }
        .detail-content {
            font-size: 11px;
            background: #222;
            padding: 10px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            color: #aaa;
        }
        .headers-list {
            font-size: 11px;
            background: #222;
            padding: 6px 10px;
        }
        .header-row {
            display: flex;
            padding: 3px 0;
        }
        .header-name {
            color: #999;
            min-width: 160px;
            flex-shrink: 0;
        }
        .header-value { color: #ccc; word-break: break-all; }
        .tabs {
            display: flex;
            gap: 0;
            border-bottom: 1px solid #333;
            margin-bottom: 12px;
        }
        .tab {
            padding: 6px 12px;
            font-size: 11px;
            color: #666;
            cursor: pointer;
            border-bottom: 1px solid transparent;
            margin-bottom: -1px;
        }
        .tab:hover { color: #999; }
        .tab.active { color: #ccc; border-bottom-color: #888; }
        .tab.disabled { color: #444; cursor: not-allowed; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .pending { color: #666; font-style: italic; padding: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Local HTTP Inspector</h1>
            <div class="info">Monitoring port {{.Port}} | Auto-refresh: 3s</div>
        </div>
        <div class="controls">
            <input type="text" id="search" placeholder="Filter by URL path..." autocomplete="off">
            <span class="badge">{{.Count}} requests</span>
            <a href="/clear" onclick="return confirm('Clear all packets?')">Clear</a>
        </div>
    </div>
    <div class="container">
        {{if eq .Count 0}}
        <div class="empty">
            <h2>No packets captured yet</h2>
            <p>Waiting for HTTP traffic on port {{.Port}}...</p>
        </div>
        {{else}}
        <div class="packet-list">
            {{range .Packets}}
            <div class="packet" data-id="{{.ID}}" onclick="togglePacket(this, event)">
                <div class="packet-header">
                    {{if eq .Type "request"}}
                    <span class="method {{.Method}}">{{.Method}}</span>
                    <span class="url">{{.URL}}</span>
                    {{else}}
                    <span class="method RES">RES</span>
                    <span class="status s{{.StatusClass}}">{{.Status}}</span>
                    <span class="url">{{.ContentType}}</span>
                    {{end}}
                    <span class="size">{{.BodySize}}B</span>
                    <span class="timestamp">{{.TimestampStr}}</span>
                </div>
                <div class="packet-details">
                    {{if eq .Type "request"}}
                    <div class="detail-section">
                        <div class="detail-title">Request Info</div>
                        <div class="detail-content">{{.Method}} {{.URL}} {{.Protocol}}
Host: {{.Host}}
Connection: {{.Connection}}</div>
                    </div>
                    {{else}}
                    <div class="detail-section">
                        <div class="detail-title">Response Info</div>
                        <div class="detail-content">{{.Protocol}} {{.Status}}
Connection: {{.Connection}}</div>
                    </div>
                    {{end}}
                    <div class="detail-section">
                        <div class="detail-title">Headers</div>
                        <div class="headers-list">
                            {{range $key, $value := .Headers}}
                            <div class="header-row">
                                <span class="header-name">{{$key}}:</span>
                                <span class="header-value">{{$value}}</span>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{if .Body}}
                    <div class="detail-section">
                        <div class="detail-header">
                            <div class="detail-title">Body</div>
                            <button class="copy-btn" onclick="copyBody(this, event)">Copy</button>
                        </div>
                        <div class="detail-content">{{.Body}}</div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
    <script>
        const expandedPairs = new Set();
        const activeTab = {};
        let allPairs = [];
        const searchInput = document.getElementById('search');

        searchInput.addEventListener('input', () => render(allPairs));

        async function refresh() {
            try {
                const resp = await fetch('/api/pairs');
                allPairs = await resp.json();
                document.querySelector('.badge').textContent = allPairs.length + ' requests';
                render(allPairs);
            } catch (e) {
                console.error('Refresh failed:', e);
            }
        }

        function togglePair(el, event) {
            if (event.target.closest('.packet-details') || event.target.closest('.tab')) return;
            const id = el.dataset.id;
            el.classList.toggle('expanded');
            if (el.classList.contains('expanded')) {
                expandedPairs.add(id);
            } else {
                expandedPairs.delete(id);
            }
        }

        function switchTab(pairId, tab, event) {
            event.stopPropagation();
            activeTab[pairId] = tab;
            render(allPairs);
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function copyBody(btn, event) {
            event.stopPropagation();
            const section = btn.closest('.detail-section');
            const content = section && section.querySelector('.detail-content');
            if (!content) return;

            const label = btn.textContent;
            const done = () => {
                btn.textContent = 'Copied';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = label;
                    btn.classList.remove('copied');
                }, 1200);
            };

            const text = content.textContent;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
            } else {
                fallbackCopy(text, done);
            }
        }

        function fallbackCopy(text, done) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try {
                document.execCommand('copy');
                done();
            } catch (e) {
                console.error('Copy failed:', e);
            }
            document.body.removeChild(ta);
        }

        function renderBody(p) {
            if (!p.body) return '';
            return '<div class="detail-section">' +
                '<div class="detail-header">' +
                '<div class="detail-title">Body (' + p.bodySize + ' bytes)</div>' +
                '<button class="copy-btn" onclick="copyBody(this, event)">Copy</button>' +
                '</div>' +
                '<div class="detail-content">' + escapeHtml(p.body) + '</div></div>';
        }

        function renderHeaders(headers) {
            return Object.entries(headers || {}).map(([k,v]) =>
                '<div class="header-row"><span class="header-name">' + escapeHtml(k) + ':</span><span class="header-value">' + escapeHtml(v) + '</span></div>'
            ).join('');
        }

        function renderPacketContent(p, type) {
            if (!p) return '<div class="pending">Waiting for ' + type + '...</div>';

            const headersHtml = renderHeaders(p.headers);
            if (type === 'request') {
                return '<div class="detail-section"><div class="detail-title">Request Info</div>' +
                    '<div class="detail-content">' + p.method + ' ' + escapeHtml(p.url) + ' ' + p.protocol + '\nHost: ' + escapeHtml(p.host) + '\nConnection: ' + escapeHtml(p.connection) + '</div></div>' +
                    '<div class="detail-section"><div class="detail-title">Headers</div><div class="headers-list">' + headersHtml + '</div></div>' +
                    renderBody(p);
            } else {
                return '<div class="detail-section"><div class="detail-title">Response Info</div>' +
                    '<div class="detail-content">' + p.protocol + ' ' + escapeHtml(p.status) + '\nConnection: ' + escapeHtml(p.connection) + '</div></div>' +
                    '<div class="detail-section"><div class="detail-title">Headers</div><div class="headers-list">' + headersHtml + '</div></div>' +
                    renderBody(p);
            }
        }

        function render(pairs) {
            const query = searchInput.value.toLowerCase().trim();
            const filtered = pairs.filter(pair => {
                if (!query) return true;
                return pair.request && pair.request.url && pair.request.url.toLowerCase().includes(query);
            });

            const container = document.querySelector('.container');
            if (filtered.length === 0) {
                container.innerHTML = '<div class="empty"><h2>' + (query ? 'No matching requests' : 'No requests captured yet') + '</h2><p>' + (query ? 'Try a different search term' : 'Waiting for HTTP traffic...') + '</p></div>';
                return;
            }

            const html = '<div class="packet-list">' + filtered.map(pair => {
                const id = String(pair.id);
                const isExpanded = expandedPairs.has(id);
                const currentTab = activeTab[id] || 'request';
                const req = pair.request;
                const res = pair.response;
                const time = new Date(pair.timestamp).toLocaleTimeString('en-GB', {hour12: false});

                const method = req ? req.method : '???';
                const url = req ? req.url : '(pending)';
                const statusCode = res ? res.statusCode : 0;
                const statusClass = statusCode >= 500 ? 's5xx' : statusCode >= 400 ? 's4xx' : statusCode >= 300 ? 's3xx' : statusCode >= 200 ? 's2xx' : '';
                const statusText = res ? res.status : 'pending';

                return '<div class="packet' + (isExpanded ? ' expanded' : '') + '" data-id="' + id + '" onclick="togglePair(this, event)">' +
                    '<div class="packet-header">' +
                    '<span class="method ' + method + '">' + method + '</span>' +
                    '<span class="url">' + escapeHtml(url) + '</span>' +
                    (res ? '<span class="status ' + statusClass + '">' + escapeHtml(statusText) + '</span>' : '<span class="status" style="color:#64748b">pending</span>') +
                    '<span class="timestamp">' + time + '</span>' +
                    '</div>' +
                    '<div class="packet-details">' +
                    '<div class="tabs">' +
                    '<div class="tab' + (currentTab === 'request' ? ' active' : '') + (req ? '' : ' disabled') + '" onclick="switchTab(\'' + id + '\', \'request\', event)">Request' + (req ? ' (' + req.bodySize + 'B)' : '') + '</div>' +
                    '<div class="tab' + (currentTab === 'response' ? ' active' : '') + (res ? '' : ' disabled') + '" onclick="switchTab(\'' + id + '\', \'response\', event)">Response' + (res ? ' (' + res.bodySize + 'B)' : '') + '</div>' +
                    '</div>' +
                    '<div class="tab-content' + (currentTab === 'request' ? ' active' : '') + '">' + renderPacketContent(req, 'request') + '</div>' +
                    '<div class="tab-content' + (currentTab === 'response' ? ' active' : '') + '">' + renderPacketContent(res, 'response') + '</div>' +
                    '</div></div>';
            }).join('') + '</div>';

            container.innerHTML = html;
        }

        setInterval(refresh, 3000);
    </script>
</body>
</html>`

// PacketView is a view model for rendering packets in the template
type PacketView struct {
	CapturedPacket
	TimestampStr string
	StatusClass  string
}

// DashboardData holds data for the dashboard template
type DashboardData struct {
	Port    int
	Count   int
	Packets []PacketView
}

// StartDashboardServer starts the web dashboard on the given port
func StartDashboardServer(dashboardPort int, capturePort int) error {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		packets := Store.GetAll()
		views := make([]PacketView, len(packets))
		for i, p := range packets {
			statusClass := ""
			if p.StatusCode >= 200 && p.StatusCode < 300 {
				statusClass = "2xx"
			} else if p.StatusCode >= 300 && p.StatusCode < 400 {
				statusClass = "3xx"
			} else if p.StatusCode >= 400 && p.StatusCode < 500 {
				statusClass = "4xx"
			} else if p.StatusCode >= 500 {
				statusClass = "5xx"
			}

			views[i] = PacketView{
				CapturedPacket: p,
				TimestampStr:   p.Timestamp.Format("15:04:05"),
				StatusClass:    statusClass,
			}
		}

		data := DashboardData{
			Port:    capturePort,
			Count:   len(Store.GetPairs()),
			Packets: views,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, data)
	})

	http.HandleFunc("/api/packets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Store.GetAll())
	})

	http.HandleFunc("/api/pairs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Store.GetPairs())
	})

	http.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
		Store.Clear()
		http.Redirect(w, r, "/", http.StatusFound)
	})

	fmt.Printf("Dashboard available at http://localhost:%d\n", dashboardPort)
	return http.ListenAndServe(fmt.Sprintf(":%d", dashboardPort), nil)
}
