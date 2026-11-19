import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BurpBridge - a Burp extension with a control panel (suite tab) and a localhost
 * control API to drive Burp's engine: send through Burp, push to Repeater,
 * clear Repeater, active scan, read history/sitemap/issues, manage scope.
 */
public class BurpBridge implements BurpExtension {
    private MontoyaApi api;
    private volatile ServerSocket server;
    private volatile boolean running = false;
    private volatile int port = 8737;

    // access control / settings
    private volatile boolean enabled = true;
    private volatile String token = "";        // if set, callers must send X-Bridge-Token
    private volatile String allowedHosts = "";  // comma-separated; empty = any

    private final Map<String, Audit> audits = new ConcurrentHashMap<>();
    private final AtomicInteger auditSeq = new AtomicInteger(1);
    private final AtomicInteger reqCount = new AtomicInteger(0);

    private JTextArea logArea;
    private JLabel statusLabel;
    private JLabel statsLabel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("BurpBridge");
        buildTab();
        startServer();
        api.extension().registerUnloadingHandler(this::stopServer);
    }

    // ---------- control panel ----------
    private void buildTab() {
        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));

        // --- Server ---
        JPanel server = section("Server");
        statusLabel = new JLabel();
        statsLabel = new JLabel();
        JButton startStop = new JButton("Stop server");
        startStop.addActionListener(e -> {
            if (running) { stopServer(); startStop.setText("Start server"); }
            else { startServer(); startStop.setText("Stop server"); }
            refreshStatus();
        });
        JTextField portField = new JTextField(String.valueOf(port), 6);
        JButton applyPort = new JButton("Apply port");
        applyPort.addActionListener(e -> {
            try { int p = Integer.parseInt(portField.getText().trim()); stopServer(); port = p; startServer(); refreshStatus(); log("port set to " + port); }
            catch (Exception ex) { log("bad port: " + ex); }
        });
        server.add(statusLabel);
        server.add(statsLabel);
        server.add(row(new JLabel("Port:"), portField, applyPort, startStop));
        controls.add(server);

        // --- Access control ---
        JPanel access = section("Access control");
        JCheckBox enabledBox = new JCheckBox("API enabled", enabled);
        enabledBox.addActionListener(e -> { enabled = enabledBox.isSelected(); log("enabled = " + enabled); });
        access.add(enabledBox);
        JTextField tokenField = new JTextField(24);
        JButton applyToken = new JButton("Apply");
        applyToken.addActionListener(e -> { token = tokenField.getText().trim(); log("access token " + (token.isEmpty() ? "cleared (open)" : "set (X-Bridge-Token required)")); });
        access.add(row(new JLabel("Token (X-Bridge-Token):"), tokenField, applyToken));
        JTextField hostsField = new JTextField(28);
        JButton applyHosts = new JButton("Apply");
        applyHosts.addActionListener(e -> { allowedHosts = hostsField.getText().trim(); log("allowed target hosts = " + (allowedHosts.isEmpty() ? "ANY" : allowedHosts)); });
        access.add(row(new JLabel("Allowed target hosts (csv, blank=any):"), hostsField, applyHosts));
        controls.add(access);

        // --- Actions ---
        JPanel actions = section("Actions");
        JButton clearBtn = new JButton("Clear Repeater");
        clearBtn.addActionListener(e -> log("Clear Repeater: closed " + clearRepeater() + " tab(s)"));
        JButton dumpBtn = new JButton("Dump Swing tree");
        dumpBtn.addActionListener(e -> log(dumpTree()));
        JButton histBtn = new JButton("History (30)");
        histBtn.addActionListener(e -> log(historyText(30)));
        JButton issuesBtn = new JButton("Scanner issues");
        issuesBtn.addActionListener(e -> log(issuesText()));
        JButton mapBtn = new JButton("Site map (50)");
        mapBtn.addActionListener(e -> log(sitemapText(50)));
        actions.add(row(clearBtn, dumpBtn, histBtn, issuesBtn, mapBtn));
        JTextField scopeField = new JTextField(24);
        JButton scopeCheck = new JButton("Check scope");
        scopeCheck.addActionListener(e -> log(scopeText("check", scopeField.getText().trim())));
        JButton scopeInc = new JButton("Include");
        scopeInc.addActionListener(e -> log(scopeText("include", scopeField.getText().trim())));
        actions.add(row(new JLabel("Scope URL:"), scopeField, scopeCheck, scopeInc));
        controls.add(actions);

        root.add(controls, BorderLayout.NORTH);

        // --- Log ---
        logArea = new JTextArea(18, 90);
        logArea.setEditable(false);
        JPanel logPanel = new JPanel(new BorderLayout(4, 4));
        logPanel.setBorder(new TitledBorder("Log"));
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);
        JButton clearLog = new JButton("Clear log");
        clearLog.addActionListener(e -> logArea.setText(""));
        JPanel logBtns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        logBtns.add(clearLog);
        logPanel.add(logBtns, BorderLayout.SOUTH);
        root.add(logPanel, BorderLayout.CENTER);

        refreshStatus();
        api.userInterface().registerSuiteTab("BurpBridge", root);
    }

    private JPanel section(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new TitledBorder(title));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private JPanel row(Component... comps) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        for (Component c : comps) p.add(c);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private void refreshStatus() {
        if (statusLabel != null)
            statusLabel.setText("Status: " + (running ? "RUNNING on http://127.0.0.1:" + port : "STOPPED"));
        if (statsLabel != null)
            statsLabel.setText("Requests served: " + reqCount.get());
    }

    private void log(String s) {
        api.logging().logToOutput("[BurpBridge] " + s);
        if (logArea != null)
            SwingUtilities.invokeLater(() -> { logArea.append(s + "\n"); logArea.setCaretPosition(logArea.getDocument().getLength()); });
    }

    // ---------- server ----------
    private void startServer() {
        if (running) return;
        try {
            server = new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
            running = true;
            Thread t = new Thread(this::acceptLoop, "BurpBridge-server");
            t.setDaemon(true);
            t.start();
            log("control server on http://127.0.0.1:" + port);
        } catch (IOException e) {
            log("failed to start server: " + e);
        }
        refreshStatus();
    }

    private void stopServer() {
        running = false;
        try { if (server != null) server.close(); } catch (IOException ignore) {}
        log("control server stopped");
        refreshStatus();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = server.accept();
                Thread h = new Thread(() -> handle(s), "BurpBridge-conn");
                h.setDaemon(true);
                h.start();
            } catch (IOException e) {
                if (running) log("accept: " + e);
            }
        }
    }

    private void handle(Socket s) {
        try (Socket sock = s) {
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            ByteArrayOutputStream head = new ByteArrayOutputStream();
            int state = 0, b;
            while ((b = in.read()) != -1) {
                head.write(b);
                if (state == 0 && b == '\r') state = 1;
                else if (state == 1 && b == '\n') state = 2;
                else if (state == 2 && b == '\r') state = 3;
                else if (state == 3 && b == '\n') break;
                else state = 0;
            }
            String[] lines = head.toString("ISO-8859-1").split("\r\n");
            if (lines.length == 0 || lines[0].isEmpty()) { write(out, 400, "bad request"); return; }
            String[] reqline = lines[0].split(" ");
            if (reqline.length < 2) { write(out, 400, "bad request"); return; }
            String method = reqline[0], target = reqline[1], path = target, queryStr = "";
            int qm = target.indexOf('?');
            if (qm >= 0) { path = target.substring(0, qm); queryStr = target.substring(qm + 1); }

            Map<String, String> headers = new HashMap<>();
            int contentLength = 0;
            for (int i = 1; i < lines.length; i++) {
                String ln = lines[i]; int c = ln.indexOf(':');
                if (c > 0) {
                    String hn = ln.substring(0, c).trim(), hv = ln.substring(c + 1).trim();
                    headers.put(hn.toLowerCase(), hv);
                    if (hn.equalsIgnoreCase("Content-Length")) { try { contentLength = Integer.parseInt(hv); } catch (Exception ignore) {} }
                }
            }
            byte[] body = new byte[contentLength];
            int off = 0;
            while (off < contentLength) { int r = in.read(body, off, contentLength - off); if (r < 0) break; off += r; }

            reqCount.incrementAndGet();
            refreshStatus();

            if (!path.equals("/ping")) {
                if (!enabled) { write(out, 403, "disabled\n"); return; }
                if (!token.isEmpty() && !token.equals(headers.get("x-bridge-token"))) { write(out, 401, "bad or missing X-Bridge-Token\n"); return; }
            }

            Map<String, String> q = parseQuery(queryStr);

            // target-host allowlist for endpoints that reach out
            if ((path.equals("/send") || path.equals("/repeater") || path.equals("/scan")) && !allowedHosts.isEmpty()) {
                String host = q.getOrDefault("host", "");
                boolean ok = false;
                for (String h : allowedHosts.split(",")) if (host.equalsIgnoreCase(h.trim())) ok = true;
                if (!ok) { write(out, 403, "host not in allowlist: " + host + "\n"); return; }
            }

            route(out, method, path, q, body);
        } catch (Exception e) { /* best effort */ }
    }

    private void route(OutputStream out, String method, String path, Map<String, String> q, byte[] body) throws IOException {
        try {
            switch (path) {
                case "/ping": write(out, 200, "BurpBridge OK\n"); return;
                case "/debug": write(out, 200, dumpTree()); return;
                case "/clear": write(out, 200, "closed " + clearRepeater() + " tab(s)\n"); return;
                case "/send": {
                    HttpRequest req = buildReq(q, body);
                    HttpMode mode = parseMode(q.getOrDefault("httpmode", ""));
                    String connId = q.getOrDefault("connid", "");
                    long t0 = System.nanoTime();
                    HttpRequestResponse rr;
                    if (!connId.isEmpty() && mode != null) rr = api.http().sendRequest(req, mode, connId);
                    else if (mode != null) rr = api.http().sendRequest(req, mode);
                    else rr = api.http().sendRequest(req);
                    long ms = (System.nanoTime() - t0) / 1_000_000L;
                    HttpResponse resp = rr.response();
                    // Prefix a bridge status line so callers see timing and null-response
                    // (a hang/timeout is the key signal in desync timing tests).
                    String meta = "X-Bridge-Elapsed-Ms: " + ms + "\r\nX-Bridge-Response: "
                            + (resp == null ? "NONE (timeout/no-response)" : String.valueOf(resp.statusCode())) + "\r\n\r\n";
                    if (resp == null) { writeBytes(out, 200, meta.getBytes(StandardCharsets.ISO_8859_1)); return; }
                    byte[] rb = resp.toByteArray().getBytes();
                    byte[] all = new byte[meta.length() + rb.length];
                    System.arraycopy(meta.getBytes(StandardCharsets.ISO_8859_1), 0, all, 0, meta.length());
                    System.arraycopy(rb, 0, all, meta.length(), rb.length);
                    writeBytes(out, 200, all); return;
                }
                case "/repeater": {
                    String name = q.getOrDefault("name", "BurpBridge");
                    api.repeater().sendToRepeater(buildReq(q, body), name);
                    write(out, 200, "sent to Repeater tab: " + name + "\n"); return;
                }
                case "/scan": {
                    HttpRequest req = buildReq(q, body);
                    Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
                    audit.addRequest(req);
                    String id = "scan" + auditSeq.getAndIncrement();
                    audits.put(id, audit);
                    write(out, 200, "started active audit id=" + id + " on " + req.method() + " " + req.url() + "\n"); return;
                }
                case "/scanstatus": {
                    Audit a = audits.get(q.getOrDefault("id", ""));
                    if (a == null) { write(out, 404, "no such audit id\n"); return; }
                    StringBuilder sb = new StringBuilder();
                    sb.append("status: ").append(a.statusMessage()).append('\n')
                      .append("requests: ").append(a.requestCount()).append("  errors: ").append(a.errorCount()).append('\n');
                    List<AuditIssue> issues = a.issues();
                    sb.append("issues: ").append(issues.size()).append('\n');
                    for (AuditIssue is : issues) sb.append("  [").append(is.severity()).append("] ").append(is.name()).append(" - ").append(is.baseUrl()).append('\n');
                    write(out, 200, sb.toString()); return;
                }
                case "/issues": write(out, 200, issuesText()); return;
                case "/issuedetail": {
                    String match = q.getOrDefault("match", "");
                    int n = Integer.parseInt(q.getOrDefault("n", "5"));
                    int maxBytes = Integer.parseInt(q.getOrDefault("maxbytes", "4000"));
                    write(out, 200, issuesDetail(match, n, maxBytes)); return;
                }
                case "/scope": write(out, 200, scopeText(q.getOrDefault("action", "check"), q.getOrDefault("url", ""))); return;
                case "/sitemap": write(out, 200, sitemapText(Integer.parseInt(q.getOrDefault("n", "50")))); return;
                case "/history": write(out, 200, historyText(Integer.parseInt(q.getOrDefault("n", "30")), q.getOrDefault("match", ""))); return;
                case "/historyfull": {
                    String match = q.getOrDefault("match", "");
                    int idx = Integer.parseInt(q.getOrDefault("i", "-1"));
                    int n = Integer.parseInt(q.getOrDefault("n", "3"));
                    int maxBytes = Integer.parseInt(q.getOrDefault("maxbytes", "32768"));
                    write(out, 200, historyFull(match, idx, n, maxBytes)); return;
                }
                case "/historystats": {
                    String match = q.getOrDefault("match", "");
                    int top = Integer.parseInt(q.getOrDefault("top", "500"));
                    int minStatus = Integer.parseInt(q.getOrDefault("minstatus", "0"));
                    int scan = Integer.parseInt(q.getOrDefault("scan", "1000000"));
                    write(out, 200, historyStats(match, top, minStatus, scan)); return;
                }
                case "/historyreq": {
                    String match = q.getOrDefault("match", "");
                    List<ProxyHttpRequestResponse> hist = api.proxy().history();
                    for (int i = hist.size() - 1; i >= 0; i--) {
                        HttpRequest rq = hist.get(i).finalRequest();
                        if (match.isEmpty() || rq.url().contains(match)) { writeBytes(out, 200, rq.toByteArray().getBytes()); return; }
                    }
                    write(out, 404, "no matching history entry\n"); return;
                }
                default: write(out, 404, "unknown endpoint\n");
            }
        } catch (Exception e) { write(out, 500, "[error] " + e + "\n"); }
    }

    // ---------- actions (shared by endpoints + buttons) ----------
    private String historyText(int n) { return historyText(n, ""); }

    // Summary of proxy history. When match is non-empty, only entries whose URL
    // contains it are shown; scans newest-first and stops after n matches, so it
    // stays fast on very large project histories. Each row is prefixed with the
    // absolute history index (#i) for use with /historyfull?i=.
    private String historyText(int n, String match) {
        List<ProxyHttpRequestResponse> hist = api.proxy().history();
        List<String> rows = new ArrayList<>();
        for (int i = hist.size() - 1; i >= 0 && rows.size() < n; i--) {
            ProxyHttpRequestResponse it = hist.get(i);
            HttpRequest rq = it.finalRequest();
            if (!match.isEmpty() && !rq.url().contains(match)) continue;
            HttpResponse rs = it.response();
            rows.add("#" + i + "  " + rq.method() + ' ' + rq.url()
                    + " -> " + (rs == null ? "-" : String.valueOf(rs.statusCode())));
        }
        StringBuilder sb = new StringBuilder("proxy history (" + rows.size() + " shown, match="
                + (match.isEmpty() ? "*" : match) + ", total " + hist.size() + ", newest first):\n");
        for (String r : rows) sb.append(r).append('\n');
        return sb.toString();
    }

    // Full request AND response (raw bytes) for matching proxy history entries.
    // Select by URL substring (match=) or by absolute history index (i=). Scans
    // newest-first, up to n entries; each message is capped at maxBytes so a large
    // body cannot blow up the response (headers are always preserved).
    private String historyFull(String match, int idx, int n, int maxBytes) {
        List<ProxyHttpRequestResponse> hist = api.proxy().history();
        StringBuilder sb = new StringBuilder();
        int shown = 0;
        int start = (idx >= 0 && idx < hist.size()) ? idx : hist.size() - 1;
        int stop = (idx >= 0) ? idx - 1 : -1;      // single entry when i= is given
        for (int i = start; i > stop && shown < n; i--) {
            ProxyHttpRequestResponse it = hist.get(i);
            HttpRequest rq = it.finalRequest();
            if (idx < 0 && !match.isEmpty() && !rq.url().contains(match)) continue;
            HttpResponse rs = it.response();
            sb.append("===== ENTRY #").append(i).append("  ").append(rq.method())
              .append(' ').append(rq.url()).append(" =====\n");
            sb.append("--- REQUEST ---\n").append(cap(rq.toByteArray().getBytes(), maxBytes)).append('\n');
            sb.append("--- RESPONSE ").append(rs == null ? "(none)" : String.valueOf(rs.statusCode()))
              .append(" ---\n");
            if (rs != null) sb.append(cap(rs.toByteArray().getBytes(), maxBytes)).append('\n');
            sb.append('\n');
            shown++;
        }
        if (shown == 0) sb.append("no matching history entry (match=").append(match)
                          .append(", i=").append(idx).append(")\n");
        return sb.toString();
    }

    private String cap(byte[] b, int max) {
        if (max <= 0 || b.length <= max) return new String(b, StandardCharsets.ISO_8859_1);
        return new String(b, 0, max, StandardCharsets.ISO_8859_1)
                + "\n...[truncated " + (b.length - max) + " bytes]...";
    }

    // Aggregate the whole proxy history (metadata only: method, URL, status) into a
    // compact review surface: status distribution, hosts, and the distinct
    // method+path endpoint list with the set of statuses seen and a hit count.
    // Scans newest-first; `scan` caps how many entries to walk (default all).
    // `match` filters by URL substring; `minstatus` keeps only responses at/above it
    // (e.g. 500 to surface server errors). No bodies are read, so it stays cheap.
    private String historyStats(String match, int top, int minStatus, int scan) {
        List<ProxyHttpRequestResponse> hist = api.proxy().history();
        java.util.TreeMap<Integer, Integer> statusDist = new java.util.TreeMap<>();
        java.util.HashMap<String, int[]> hostDist = new java.util.HashMap<>();
        java.util.HashMap<String, int[]> eps = new java.util.HashMap<>();
        java.util.HashMap<String, java.util.TreeSet<Integer>> epStatus = new java.util.HashMap<>();
        int scanned = 0, matched = 0;
        for (int i = hist.size() - 1; i >= 0 && scanned < scan; i--, scanned++) {
            ProxyHttpRequestResponse it = hist.get(i);
            HttpRequest rq = it.finalRequest();
            String url = rq.url();
            if (!match.isEmpty() && !url.contains(match)) continue;
            HttpResponse rs = it.response();
            int st = rs == null ? -1 : rs.statusCode();
            if (minStatus > 0 && st < minStatus) continue;
            matched++;
            statusDist.merge(st, 1, Integer::sum);
            String host = "";
            try { host = rq.httpService().host(); } catch (Exception e) {}
            hostDist.computeIfAbsent(host, k -> new int[1])[0]++;
            String path = url; int qm = path.indexOf('?'); if (qm >= 0) path = path.substring(0, qm);
            String key = rq.method() + " " + path;
            eps.computeIfAbsent(key, k -> new int[1])[0]++;
            epStatus.computeIfAbsent(key, k -> new java.util.TreeSet<>()).add(st);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("history stats: total=").append(hist.size()).append(" scanned=").append(scanned)
          .append(" matched=").append(matched).append(" match=").append(match.isEmpty() ? "*" : match)
          .append(minStatus > 0 ? (" minstatus=" + minStatus) : "").append('\n');
        sb.append("\nstatus distribution:\n");
        for (Map.Entry<Integer, Integer> e : statusDist.entrySet())
            sb.append("  ").append(e.getKey() == -1 ? "(no resp)" : e.getKey()).append(": ").append(e.getValue()).append('\n');
        sb.append("\nhosts:\n");
        hostDist.entrySet().stream().sorted((a, b) -> b.getValue()[0] - a.getValue()[0]).limit(40)
            .forEach(e -> sb.append("  ").append(e.getKey()).append(": ").append(e.getValue()[0]).append('\n'));
        sb.append("\nendpoints (top ").append(top).append(" by count; method path [statuses] xN):\n");
        eps.entrySet().stream().sorted((a, b) -> b.getValue()[0] - a.getValue()[0]).limit(top)
            .forEach(e -> sb.append("  ").append(e.getKey()).append(" ").append(epStatus.get(e.getKey()))
                .append(" x").append(e.getValue()[0]).append('\n'));
        return sb.toString();
    }

    private String issuesText() {
        List<AuditIssue> issues = api.siteMap().issues();
        StringBuilder sb = new StringBuilder("scanner issues: " + issues.size() + "\n");
        for (AuditIssue is : issues) sb.append("  [").append(is.severity()).append("] ").append(is.name()).append(" - ").append(is.baseUrl()).append('\n');
        return sb.toString();
    }

    // Full detail for issues whose name or URL contains `match`: severity AND confidence
    // (Tentative/Firm/Certain - vital for triaging smuggling/timing findings), the detail
    // text, and the evidence request+response for each. Bodies capped at maxBytes.
    private String issuesDetail(String match, int n, int maxBytes) {
        List<AuditIssue> issues = api.siteMap().issues();
        StringBuilder sb = new StringBuilder();
        int shown = 0;
        String m = match.toLowerCase();
        for (AuditIssue is : issues) {
            String hay = (is.name() + " " + is.baseUrl()).toLowerCase();
            if (!match.isEmpty() && !hay.contains(m)) continue;
            if (shown >= n) break;
            shown++;
            sb.append("======================================================\n");
            sb.append("[").append(is.severity()).append(" / confidence ").append(is.confidence()).append("] ")
              .append(is.name()).append('\n').append(is.baseUrl()).append('\n');
            String det = is.detail();
            if (det != null && !det.isEmpty())
                sb.append("--- detail ---\n").append(det.length() > maxBytes ? det.substring(0, maxBytes) + "\n...[truncated]" : det).append('\n');
            int mi = 0;
            for (HttpRequestResponse rr : is.requestResponses()) {
                sb.append("--- evidence msg ").append(mi++).append(" ---\n");
                HttpRequest rq = rr.request();
                if (rq != null) sb.append("REQUEST:\n").append(cap(rq.toByteArray().getBytes(), maxBytes)).append('\n');
                HttpResponse rs = rr.response();
                sb.append("RESPONSE: ").append(rs == null ? "(none)" : String.valueOf(rs.statusCode())).append('\n');
                if (rs != null) sb.append(cap(rs.toByteArray().getBytes(), Math.min(maxBytes, 1000))).append('\n');
            }
        }
        sb.insert(0, "matched issues: " + shown + " (match=" + (match.isEmpty() ? "*" : match) + ", total " + issues.size() + ")\n");
        return sb.toString();
    }

    private String sitemapText(int n) {
        List<HttpRequestResponse> rrs = api.siteMap().requestResponses();
        StringBuilder sb = new StringBuilder("site map (last " + n + " of " + rrs.size() + "):\n");
        for (int i = Math.max(0, rrs.size() - n); i < rrs.size(); i++) {
            HttpRequestResponse rr = rrs.get(i);
            HttpResponse rs = rr.response();
            sb.append(rr.request().method()).append(' ').append(rr.request().url())
              .append(" -> ").append(rs == null ? "-" : String.valueOf(rs.statusCode())).append('\n');
        }
        return sb.toString();
    }

    private String scopeText(String action, String url) {
        if ("include".equals(action)) { api.scope().includeInScope(url); return "included: " + url + "\n"; }
        if ("exclude".equals(action)) { api.scope().excludeFromScope(url); return "excluded: " + url + "\n"; }
        return "inScope(" + url + ") = " + api.scope().isInScope(url) + "\n";
    }

    // ---------- Swing introspection / Repeater control ----------
    private String dumpTree() {
        StringBuilder sb = new StringBuilder("--- Swing tree (JTabbedPanes) ---\n");
        try {
            Frame f = api.userInterface().swingUtils().suiteFrame();
            List<JTabbedPane> panes = new ArrayList<>();
            collectTabbedPanes(f, panes);
            int idx = 0;
            for (JTabbedPane tp : panes) {
                sb.append("TabbedPane#").append(idx++).append(" tabs=").append(tp.getTabCount()).append(" [");
                for (int i = 0; i < tp.getTabCount(); i++) sb.append(i == 0 ? "" : ", ").append(tp.getTitleAt(i));
                sb.append("]\n");
            }
            JTabbedPane rep = findRepeaterPane();
            if (rep != null) {
                sb.append("\n--- Repeater pane detail (").append(rep.getTabCount()).append(" tabs) ---\n");
                for (int i = 0; i < rep.getTabCount(); i++) {
                    Component c = rep.getComponentAt(i);
                    sb.append(i).append(": '").append(rep.getTitleAt(i)).append("' -> ").append(c == null ? "null" : c.getClass().getName());
                    if (c instanceof Container) sb.append(" children=").append(((Container) c).getComponentCount());
                    sb.append('\n');
                }
            }
        } catch (Exception e) { sb.append("error: ").append(e).append("\n"); }
        return sb.toString();
    }

    private void collectTabbedPanes(Component c, List<JTabbedPane> out) {
        if (c instanceof JTabbedPane) out.add((JTabbedPane) c);
        if (c instanceof Container) for (Component child : ((Container) c).getComponents()) collectTabbedPanes(child, out);
    }

    private JTabbedPane findRepeaterPane() {
        Frame f = api.userInterface().swingUtils().suiteFrame();
        List<JTabbedPane> panes = new ArrayList<>();
        collectTabbedPanes(f, panes);
        java.util.Set<String> editorTitles = new java.util.HashSet<>(java.util.Arrays.asList(
                "Pretty", "Raw", "Hex", "Render", "Inspector", "Notes", "Explanations", "Custom actions"));
        JTabbedPane best = null; int bestCount = 0;
        for (JTabbedPane tp : panes) {
            boolean toolSelector = false, allEditor = tp.getTabCount() > 0;
            for (int i = 0; i < tp.getTabCount(); i++) {
                String t = tp.getTitleAt(i);
                if ("Dashboard".equals(t) || "Repeater".equals(t)) toolSelector = true;
                if (t == null || !editorTitles.contains(t)) allEditor = false;
            }
            if (toolSelector || allEditor) continue;
            if (tp.getTabCount() > bestCount) { bestCount = tp.getTabCount(); best = tp; }
        }
        return best;
    }

    private int clearRepeater() {
        final int[] closed = {0};
        try {
            final JTabbedPane target = findRepeaterPane();
            if (target == null) { log("clearRepeater: could not locate Repeater pane"); return 0; }
            Runnable r = () -> {
                for (int i = target.getTabCount() - 1; i >= 0; i--) {
                    String t = target.getTitleAt(i);
                    if (t == null || t.isEmpty()) continue;
                    try { target.removeTabAt(i); closed[0]++; } catch (Exception ignore) {}
                }
            };
            if (SwingUtilities.isEventDispatchThread()) r.run(); else SwingUtilities.invokeAndWait(r);
        } catch (Exception e) { log("clearRepeater error: " + e); }
        return closed[0];
    }

    // ---------- helpers ----------
    // Map an httpmode query value to a Montoya HttpMode. Empty/unknown = null (auto,
    // via the no-mode overload). "1"/"http1"=HTTP_1, "2"=HTTP_2, "2ia"=HTTP_2_IGNORE_ALPN.
    private HttpMode parseMode(String v) {
        if (v == null) return null;
        switch (v.toLowerCase()) {
            case "1": case "http1": case "http_1": return HttpMode.HTTP_1;
            case "2": case "http2": case "http_2": return HttpMode.HTTP_2;
            case "2ia": case "http_2_ignore_alpn": return HttpMode.HTTP_2_IGNORE_ALPN;
            case "auto": return HttpMode.AUTO;
            default: return null;
        }
    }

    private HttpRequest buildReq(Map<String, String> q, byte[] body) {
        String host = q.getOrDefault("host", "");
        int p = Integer.parseInt(q.getOrDefault("port", "443"));
        String tlsv = q.getOrDefault("tls", "1");
        boolean tls = !"0".equals(tlsv) && !"false".equalsIgnoreCase(tlsv);
        return HttpRequest.httpRequest(HttpService.httpService(host, p, tls), ByteArray.byteArray(body));
    }

    private Map<String, String> parseQuery(String qs) {
        Map<String, String> m = new HashMap<>();
        if (qs == null || qs.isEmpty()) return m;
        for (String p : qs.split("&")) {
            int i = p.indexOf('=');
            if (i > 0) try { m.put(URLDecoder.decode(p.substring(0, i), "UTF-8"), URLDecoder.decode(p.substring(i + 1), "UTF-8")); } catch (Exception ignore) {}
        }
        return m;
    }

    private void write(OutputStream out, int code, String s) throws IOException { writeBytes(out, code, s.getBytes(StandardCharsets.UTF_8)); }

    private void writeBytes(OutputStream out, int code, byte[] body) throws IOException {
        String hdr = "HTTP/1.1 " + code + " X\r\nContent-Length: " + body.length + "\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n";
        out.write(hdr.getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }
}
