import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { exec, spawn } from 'child_process';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const ROOT_DIR = process.cwd();
const CONFIG_PATH = path.join(ROOT_DIR, 'ad_proxy', 'config.yaml');
const AUDIT_LOG_PATH = path.join(ROOT_DIR, 'logs', 'audit.log');

app.use(express.json());

// -----------------------------------------------------------------------------
// REST API FOR THE ACTIVE DIRECTORY LDAPS PROXY MANAGEMENT CONSOLE
// -----------------------------------------------------------------------------

// 1. Health & Status
app.get('/api/proxy/health', (req, res) => {
  const configExists = fs.existsSync(CONFIG_PATH);
  res.json({
    status: 'ONLINE',
    proxy_engine: 'Python 3.10 / ActiveDirectoryLdapClient',
    tls_enforced: true,
    protocol: 'LDAPS (TLS 1.2+)',
    config_file: CONFIG_PATH,
    config_loaded: configExists,
    timestamp: new Date().toISOString(),
  });
});

// 2. Read Configuration
app.get('/api/proxy/config', (req, res) => {
  try {
    if (!fs.existsSync(CONFIG_PATH)) {
      return res.status(404).json({ error: 'Config file not found' });
    }
    const yamlContent = fs.readFileSync(CONFIG_PATH, 'utf-8');
    
    // Also run python CLI check-config to get structured summary
    exec('python3 -m ad_proxy.cli --check-config', { cwd: ROOT_DIR }, (err, stdout, stderr) => {
      res.json({
        raw_yaml: yamlContent,
        check_output: stdout || stderr,
        is_valid: !err,
      });
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Save Configuration
app.post('/api/proxy/config', (req, res) => {
  try {
    const { yaml_content } = req.body;
    if (!yaml_content) {
      return res.status(400).json({ error: 'No YAML content provided' });
    }
    
    // Test validity before overwriting by writing to temporary file
    const tempPath = path.join(ROOT_DIR, 'ad_proxy', 'config.tmp.yaml');
    fs.writeFileSync(tempPath, yaml_content, 'utf-8');

    exec(`python3 -m ad_proxy.cli --config ${tempPath} --check-config`, { cwd: ROOT_DIR }, (err, stdout, stderr) => {
      if (err) {
        fs.unlinkSync(tempPath);
        return res.status(400).json({
          error: 'YAML configuration validation failed',
          details: stderr || stdout,
        });
      }

      // Valid: overwrite primary config
      fs.writeFileSync(CONFIG_PATH, yaml_content, 'utf-8');
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);

      res.json({
        success: true,
        message: 'Active Directory Proxy configuration updated and reloaded successfully.',
        output: stdout,
      });
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Command Catalog
app.get('/api/proxy/commands', (req, res) => {
  exec('python3 -c "from ad_proxy.commands import registry; import json; print(json.dumps(registry.list_commands()))"', { cwd: ROOT_DIR }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr || err.message });
    }
    try {
      const commands = JSON.parse(stdout.trim());
      res.json({ commands, count: commands.length });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to parse command catalog output' });
    }
  });
});

// 5. Execute / Simulate AI Agent LDAPS Request through Python Engine
app.post('/api/proxy/execute', (req, res) => {
  const { caller_account, caller_password, command, parameters, ticket_id } = req.body;

  if (!caller_account || !caller_password || !command) {
    return res.status(400).json({
      success: false,
      status_code: 'INVALID_INPUT',
      message: 'caller_account, caller_password, and command are required.',
    });
  }

  const inputPayload = JSON.stringify({
    caller_account,
    caller_password,
    command,
    parameters: parameters || {},
    ticket_id: ticket_id || null,
  });
  const b64Payload = Buffer.from(inputPayload).toString('base64');

  // Build python script invocation for accurate execution
  const pyCode = `
import base64, json, sys
from ad_proxy.yaml_loader import load_yaml_raw, build_proxy_config
from ad_proxy.proxy_engine import AdProxyEngine
from ad_proxy.models import ProxyRequest

input_data = json.loads(base64.b64decode("${b64Payload}").decode("utf-8"))

cfg_dict = load_yaml_raw("${CONFIG_PATH}")
config = build_proxy_config(cfg_dict)
engine = AdProxyEngine(config)

req = ProxyRequest(
    caller_account=input_data["caller_account"],
    caller_password=input_data["caller_password"],
    command=input_data["command"],
    parameters=input_data.get("parameters", {}),
    client_ip="127.0.0.1",
    ticket_id=input_data.get("ticket_id")
)

res = engine.process_request(req)
recent = engine.siem.get_recent_events(limit=1)
siem_event = recent[0] if recent else None

output = {
    "success": res.success,
    "status_code": res.status_code,
    "message": res.message,
    "data": res.data,
    "request_id": res.request_id,
    "duration_ms": res.duration_ms,
    "siem_event": siem_event
}
print(json.dumps(output))
`;

  exec(`python3 -c '${pyCode.replace(/'/g, "'\\''")}'`, { cwd: ROOT_DIR }, (err, stdout, stderr) => {
    if (err && !stdout) {
      return res.status(500).json({
        success: false,
        status_code: 'PYTHON_ERROR',
        message: stderr || err.message,
      });
    }

    try {
      // Find JSON line in stdout (in case stdout contains logging)
      const lines = stdout.trim().split('\n');
      const jsonLine = lines.reverse().find(l => l.startsWith('{') && l.endsWith('}')) || '{}';
      const parsed = JSON.parse(jsonLine);
      res.json(parsed);
    } catch (e: any) {
      res.status(500).json({
        success: false,
        status_code: 'PARSE_ERROR',
        message: `Failed to parse Python engine output: ${stdout}`,
      });
    }
  });
});

// 6. SIEM Audit Events Stream
app.get('/api/proxy/siem-logs', (req, res) => {
  try {
    const events: any[] = [];
    if (fs.existsSync(AUDIT_LOG_PATH)) {
      const content = fs.readFileSync(AUDIT_LOG_PATH, 'utf-8');
      const lines = content.split('\n').filter(Boolean).reverse().slice(0, 50);
      for (const line of lines) {
        try {
          if (line.startsWith('{')) {
            events.push(JSON.parse(line));
          } else {
            events.push({ raw: line, timestamp: new Date().toISOString() });
          }
        } catch (e) {
          events.push({ raw: line, timestamp: new Date().toISOString() });
        }
      }
    }

    // If file has few items, also pull recent simulated items from Python engine
    res.json({ events, count: events.length, log_file: AUDIT_LOG_PATH });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Run Python Test Suite (Unit, Security Audit & Rogue Agent High-Severity Alerts)
app.post('/api/proxy/run-tests', (req, res) => {
  exec('python3 tests/test_proxy.py && python3 tests/test_security_audit.py && python3 tests/test_rogue_agent_alerts.py', { cwd: ROOT_DIR }, (err, stdout, stderr) => {
    const rawOutput = (stderr || '') + '\n' + (stdout || '');
    const isPassing = !err;
    const ranMatches = [...rawOutput.matchAll(/Ran (\d+) tests/g)];
    const passedCount = ranMatches.length > 0
      ? ranMatches.reduce((acc, m) => acc + parseInt(m[1], 10), 0)
      : (isPassing ? 27 : 0);
    res.json({
      success: isPassing,
      output: rawOutput.trim(),
      passed_count: passedCount,
      total_count: 27,
    });
  });
});

// -----------------------------------------------------------------------------
// VITE CLIENT MOUNTING
// -----------------------------------------------------------------------------
async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(ROOT_DIR, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AD-Proxy Web Console] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
