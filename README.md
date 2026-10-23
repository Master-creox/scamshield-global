<h1 align="center">🛡️ ScamShield Global</h1>
<h3 align="center">Multi-Layer Scam Protection — in C++, Java, JavaScript & HTML</h3>

<p align="center">
  <i>One shield, four layers. Wherever a scam reaches you — a link, a message, a browser tab — a layer is already watching, and every verdict comes with its reasons.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C++-17-00599C?logo=cplusplus&logoColor=white">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white">
  <img src="https://img.shields.io/badge/JavaScript-ES6-F7DF1E?logo=javascript&logoColor=black">
  <img src="https://img.shields.io/badge/HTML-5-E34F26?logo=html5&logoColor=white">
  <img src="https://img.shields.io/badge/License-MIT-green">
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen">
</p>

---

## 🎯 The Problem

Scams are now the world's most common cybercrime — fake KYC SMS, phishing links,
prize bait, "digital arrest" calls, task/job scams, crypto doubling. They succeed
because each attack arrives on a *different surface* (browser, SMS, WhatsApp)
while most protection tools guard only one.

## 🧱 The Answer: Four Layers, One Brain

| Layer | Tech | Guards | What it does |
|---|---|---|---|
| ⚡ **URL Risk Engine** | **C++17** | Links anywhere | Blocklist lookup, **typosquat detection** (Levenshtein edit-distance vs 20 protected brands), punycode / raw-IP / `@`-trick / subdomain / TLD heuristics |
| ☕ **Message Analyzer** | **Java 21** | SMS · WhatsApp · Email | 10 scam-pattern categories — OTP theft, KYC threats, prize bait, task scams, **digital arrest**, crypto doubling — every point explained |
| 🌐 **Web Shield** | **JavaScript + HTML/CSS** | Your browser | The same URL + message logic as a web app. **100% client-side: pasted content never leaves your device** |
| 🧩 **Browser Extension** | **JavaScript (MV3)** | Every tab | One-click risk check of the page you're on, using the shared JS core |

All layers share the same data (`data/brands.txt`, `data/blocklist.txt`) and the
same philosophy: **explainable scores, never black boxes.**

## 📊 Verified Results (bundled test sets)

| Component | Test set | Result |
|---|---|---|
| C++ URL engine | 22 labeled URLs (12 scam, 10 legit) | **100% accuracy · 0 false positives** |
| Java message analyzer | 10 labeled messages (5 scam, 5 legit) | **100% accuracy** |
| JS web shield | Same 22 URLs + message cases | **100%** |

> My favourite detail: a *real* bank OTP SMS scores **0** (it tells you *not* to
> share), while a scam asking you to share the OTP scores **90**. The shield
> understands intent, not just keywords.

## 🚀 Quickstart

**C++ engine** (no dependencies):
```bash
cd cpp-engine && make
./scam_engine check "http://paypa1-secure.top/login"
./scam_engine batch ../data/test_urls.csv     # full evaluation
```

**Java analyzer**:
```bash
cd java-analyzer
javac ScamMessageAnalyzer.java
java ScamMessageAnalyzer                       # built-in evaluation + demo
java ScamMessageAnalyzer "Dear customer, your account will be blocked. Share your OTP"
```

**Web shield**: open `web/index.html` in any browser — that's it.

**Extension**: Chrome/Edge → `chrome://extensions` → Developer mode →
*Load unpacked* → select the `extension/` folder.

## 🧠 How Scoring Works

Every signal adds explainable points: blocklist hit **+100 (final)** · typosquat
of a brand **+45** · brand hidden before `@` **+35** · raw-IP host **+25** ·
punycode **+20** · scam keywords **+7 each** … Verdicts: **≥60 SCAM** ·
**30–59 SUSPICIOUS** · **<30 LIKELY SAFE**. Full model: [docs/architecture.md](docs/architecture.md).

## ⚠️ Honest Note on "100% Protection"

No tool on Earth can honestly guarantee 100% protection — anyone who claims
that is running the oldest scam of all. What ScamShield does is layer
*independent* checks (a scam must defeat all of them at once) and teach you the
pattern behind every verdict, so your own judgement becomes the final layer.

## 🗺️ Roadmap
- [ ] Real-time blocklist sync from public phishing feeds (PhishTank / URLhaus)
- [ ] Phone-number & UPI-ID reputation checker
- [ ] Hindi + regional-language message patterns
- [ ] ML classifier trained on a public phishing corpus, compared against the rule engine

## 📄 License
MIT — © Akash Kumar. Built as an educational project by a cybersecurity student
who believes awareness is the strongest firewall.

<p align="center"><i>Part of the CreoX Tech Labs security series · Stay Aware, Stay Secure 🔐</i></p>
