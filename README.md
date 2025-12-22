# AEGIS Shield | Next-Gen AI Web Application Firewall

![Project Status](https://img.shields.io/badge/Status-Active-success.svg?style=for-the-badge)
![Security Level](https://img.shields.io/badge/Security-Enterprise_Ready-blue.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

AEGIS Shield is a professional-grade, hybrid Web Application Firewall (WAF) that combines traditional signature-based detection with advanced Machine Learning (ML) anomaly analysis. Designed for Security Operations Centers (SOC), it provides high-density traffic visualization, real-time threat intelligence, and automated incident response.

## 🚀 Key Features

### 🛡️ Hybrid Detection Engine
*   **Signature-Based Protection**: Real-time filtering for SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, and RCE/WebShell patterns using optimized regular expressions.
*   **AI Anomaly Detection**: Utilizes an **Isolation Forest** ML model to detect zero-day attacks and payload irregularities by analyzing feature vectors (entropy, character density, length).

### 📊 Security Operations Center (SOC) Dashboard
*   **High-Density Visualization**: Minimalist, professional dark-mode UI focused on data clarity.
*   **Live Traffic Monitor**: Low-latency feed showing source IPs, GeoIP data, endpoint targeting, and risk classifications.
*   **Threat Intelligence**: Advanced breakdown of attack vectors and geographic threat distribution.

### ⚙️ Automated Incident Response
*   **Adaptive Reputation System**: Dynamic risk scoring per IP address.
*   **Auto-Blacklisting**: Persistent banning of repeat offenders based on reputation penalties.
*   **Bot Mitigation**: Integrated detection for crawlers, scrapers, and malicious curl/wget scripts.

## 🛠️ Technology Stack
*   **Core Engine**: Node.js & Express
*   **AI/ML Service**: Python (FastAPI/Scikit-learn)
*   **Frontend**: Professional CSS (Glassmorphism), Chart.js
*   **Forensics**: GeoIP-lite, UA-Parser

## 🏁 Getting Started

### Prerequisites
*   Node.js v16+
*   Python 3.8+

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/aegis-shield.git
   cd aegis-shield
   ```

2. Install Backend dependencies:
   ```bash
   cd backend
   npm install
   ```

3. Install ML dependencies:
   ```bash
   cd ../ml
   pip install -r requirements.txt
   ```

### Running Locally
1. Start the ML API:
   ```bash
   cd ml
   python api.py
   ```

2. Start the WAF Engine (in a new terminal):
   ```bash
   cd backend
   node waf-enhanced.js
   ```

3. Open the Dashboard:
   Navigate to `http://localhost:3000` in your browser.

## 📈 Evolution
For a detailed look at how this project evolved from a visual concept to an enterprise security tool, see the [EVOLUTION_REPORT.md](./EVOLUTION_REPORT.md).

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
