# ScamShield Global — Architecture

One detection philosophy, implemented in four layers so protection exists
wherever a scam reaches you — a link, a message, a browser tab.

```
                 ┌──────────────────────────────────────────────┐
   A link  ────▶ │  C++ URL Engine (cpp-engine/)                │
                 │  blocklist · typosquat (Levenshtein) ·       │
                 │  punycode/IP/@-trick/TLD heuristics          │
                 ├──────────────────────────────────────────────┤
  A message ───▶ │  Java Message Analyzer (java-analyzer/)     │
                 │  10 pattern categories: OTP theft, KYC       │
                 │  threats, prize bait, task scams, digital    │
                 │  arrest, crypto doubling...                  │
                 ├──────────────────────────────────────────────┤
  In browser ──▶ │  JavaScript Web Shield (web/)               │
                 │  same URL + message logic, 100% client-side  │
                 ├──────────────────────────────────────────────┤
   Any tab ────▶ │  Browser Extension (extension/, MV3)         │
                 │  one-click check of the current tab's URL    │
                 └──────────────────────────────────────────────┘
        Shared data: data/brands.txt · data/blocklist.txt
```

## Design principles
1. **Explainable, always.** Every score lists the exact signals that produced
   it. A shield you cannot question is a black box, not protection.
2. **Privacy by architecture.** The web shield and extension run fully
   client-side; pasted messages never leave the device.
3. **Zero-dependency cores.** C++17 standard library only; Java with no
   external libraries; vanilla JS. Clone and run — no supply chain.
4. **Honest limits.** No system can guarantee 100% protection. ScamShield
   layers independent checks so a scam must defeat all of them, and teaches
   the user the pattern behind every verdict.

## Scoring model (URL layers)
| Signal | Points |
|---|---|
| Domain on known-scam blocklist | 100 (final) |
| Typosquat of a protected brand (edit distance ≤ 2) | +45 |
| Brand hidden before '@' (userinfo deception) | +35 |
| Brand name inside a non-official domain | +35 |
| Raw IP host | +25 |
| Punycode (homograph) | +20 |
| '@' in URL | +20 |
| Many subdomains (≥ 4 labels) | +15 |
| Scam keywords (per hit, capped) | +7 |
| High-abuse TLD | +10 |
| Digits in brand-like name | +10 |
| Verdicts | ≥60 SCAM · 30–59 SUSPICIOUS · <30 LIKELY SAFE |
