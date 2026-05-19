# WAF-Web-Application-Firewall

An enterprise-grade Web Application Firewall (WAF) dashboard built for real-time security monitoring, threat analysis, and ethical testing. Designed for Nepal's critical infrastructure (NTC/Ncell gateways).

## Features

- **Security Overview** - Real-time metrics, traffic charts (Allowed/Blocked/Challenged), attack vector analysis, threat origin tracking, and live alerts
- **WAF Rules Engine** - Managed rulesets (OWASP, Bots, Custom) with filtering, search, toggle, action change, create, and delete
- **Regional Routing** - BGP topology and edge node health for Nepal datacenters (KTM-DC-01, PKR-Edge-02, LAL-DC-03)
- **Ethical Testing Lab** - Burp Suite proxy simulation, SQLMap automation, WafW00f probing, and interactive payload sandbox
- **Generate Report** - One-click PDF-ready security report with threat breakdown

## Tech Stack

- **Frontend**: HTML, Tailwind CSS, Chart.js, Vanilla JS
- **Backend**: Node.js, Express, Socket.io, CORS

## Getting Started

```bash
# Install dependencies
npm install

# Start the server
npm start

# Or use nodemon for development
npm run dev
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/rulesets` | GET | List/filter/search WAF rules |
| `/api/rulesets` | POST | Create custom rule |
| `/api/rulesets/:id` | PATCH | Update rule action |
| `/api/rulesets/:id/toggle` | PATCH | Toggle rule on/off |
| `/api/rulesets/:id` | DELETE | Delete custom rule |
| `/api/burp/start` | POST | Start Burp proxy |
| `/api/burp/stop` | POST | Stop Burp proxy |
| `/api/burp/logs` | GET | Get proxy logs |
| `/api/sqlmap/scan` | POST | Run SQLMap scan |
| `/api/wafw00f/analyze` | POST | Run WafW00f analysis |
| `/api/sandbox/fire` | POST | Test payload against WAF |
| `/api/alerts` | GET | Recent security alerts |
| `/api/threat-origin` | GET | Threat origin by country |
| `/api/report` | GET | Generate security report |

## Login

Default credentials: any username/password (frontend simulation)
