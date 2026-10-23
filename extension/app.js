// ScamShield Global - JavaScript detection core (web + extension layer)
// Mirrors the C++ URL engine and the Java message analyzer so all layers agree.

const BRANDS = {
  google: "google.com", youtube: "youtube.com", facebook: "facebook.com",
  instagram: "instagram.com", amazon: "amazon.com", netflix: "netflix.com",
  paypal: "paypal.com", apple: "apple.com", microsoft: "microsoft.com",
  whatsapp: "whatsapp.com", telegram: "telegram.org", binance: "binance.com",
  coinbase: "coinbase.com", sbi: "sbi.co.in", hdfcbank: "hdfcbank.com",
  icicibank: "icicibank.com", paytm: "paytm.com", phonepe: "phonepe.com",
  flipkart: "flipkart.com", steam: "steampowered.com",
};
const BLOCKLIST = new Set([
  "google-security-check.xyz", "paypa1-secure.top", "free-iphone-winner.click",
  "amazon-prize-claim.buzz", "bank-kyc-update-now.xyz", "crypto-double-return.top",
  "netflix-billing-fail.click", "whatsapp-gold-upgrade.xyz",
  "irs-tax-refund-fast.top", "steam-free-nitro.click",
]);
const RISKY_TLDS = new Set(["xyz", "top", "click", "buzz", "live", "club", "site", "online", "fun", "icu", "work"]);
const URL_KEYWORDS = ["verify","login","secure","bonus","free","claim","prize","wallet","kyc","update","billing","refund","winner"];

function levenshtein(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++)
      cur[j] = Math.min(prev[j] + 1, cur[j-1] + 1, prev[j-1] + (a[i-1] === b[j-1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

function registrable(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  const two = new Set(["co","com","net","org","ac","gov"]);
  if (p.length >= 3 && two.has(p[p.length-2]) && p[p.length-1].length === 2)
    return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

function analyzeUrl(rawUrl) {
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(`+${pts} ${why}`); };
  let u;
  try { u = new URL(rawUrl.startsWith("http") ? rawUrl : "http://" + rawUrl); }
  catch { return { score: 0, verdict: "INVALID URL", reasons: ["Could not parse this URL."] }; }
  const host = u.hostname.toLowerCase();
  const reg = registrable(host);
  const lower = rawUrl.toLowerCase();

  if (BLOCKLIST.has(host) || BLOCKLIST.has(reg)) {
    return { score: 100, verdict: "SCAM / HIGH RISK", reasons: ["+100 domain is on the known-scam blocklist"] };
  }
  if (Object.values(BRANDS).includes(reg))
    return { score: 2, verdict: "SAFE", reasons: ["+0 official domain of a protected brand"] };

  const stem = reg.split(".")[0];
  const tokens = stem.split("-");
  outer:
  for (const [brand, domain] of Object.entries(BRANDS)) {
    if (stem !== brand && levenshtein(stem, brand) <= 2) { add(45, `domain imitates brand '${brand}' (not ${domain})`); break; }
    if (stem !== brand && stem.includes(brand)) { add(35, `domain contains brand name '${brand}' but is not ${domain}`); break; }
    for (const tok of tokens) {
      if (tok.length < 4) continue;
      if (tok !== brand && levenshtein(tok, brand) <= 2) { add(45, `domain token '${tok}' imitates brand '${brand}'`); break outer; }
      if (tok !== brand && brand.includes(tok)) { add(35, `domain token '${tok}' is part of brand '${brand}' but domain is not ${domain}`); break outer; }
    }
  }
  const noScheme = lower.replace(/^https?:\/\//, "");
  const at = noScheme.indexOf("@"), slash = noScheme.indexOf("/");
  if (at !== -1 && (slash === -1 || at < slash)) {
    add(20, "'@' in URL hides the real destination");
    const uiStem = noScheme.slice(0, at).split(".")[0];
    for (const brand of Object.keys(BRANDS))
      if (noScheme.slice(0, at).includes(brand) || levenshtein(uiStem, brand) <= 2) {
        add(35, `brand '${brand}' appears before '@' - the real destination is a different host`); break;
      }
  }
  if (lower.includes("xn--")) add(20, "punycode domain (homograph-attack technique)");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(25, "host is a raw IP address instead of a domain");
  const parts = host.split(".");
  if (parts.length >= 4) add(15, `many subdomains (${parts.length}) used to disguise the real domain`);
  if (RISKY_TLDS.has(parts[parts.length-1])) add(10, `high-abuse TLD (.${parts[parts.length-1]})`);
  const kwHits = URL_KEYWORDS.filter(k => lower.includes(k)).length;
  if (kwHits) add(Math.min(20, kwHits * 7), `scam keywords in URL (${kwHits} found)`);
  const digits = (stem.match(/\d/g) || []).length;
  if (digits >= 2) add(10, "digits inside the brand-like name (character substitution)");
  if (rawUrl.length > 75) add(10, "unusually long URL");
  if (lower.startsWith("http://")) add(5, "plain HTTP (no encryption)");

  score = Math.min(100, score);
  const verdict = score >= 60 ? "SCAM / HIGH RISK" : score >= 30 ? "SUSPICIOUS" : "LIKELY SAFE";
  return { score, verdict, reasons };
}

// ---------- Message analysis (mirrors the Java analyzer) ----------
const MESSAGE_RULES = [
  ["OTP / PIN request", 45, ["share your otp","send otp","otp batao","share the otp","enter your pin","share your pin","cvv","send the code sent"],
   "Banks NEVER ask for OTP, PIN or CVV. Asking = scam, always."],
  ["Prize / lottery bait", 30, ["you have won","you won","lottery","lucky draw","prize","crore","winner selected","claim your reward","jackpot"],
   "Prizes you never entered for are bait."],
  ["KYC / account-block threat", 30, ["kyc","account will be blocked","account blocked","suspended within","verify your account","pan card update","aadhaar update","sim will be blocked","connection will be cut"],
   "Blocking threats are pressure tactics, not real policy."],
  ["Urgency pressure", 15, ["urgent","immediately","within 24 hours","within 2 hours","last chance","act now","expires today","turant","abhi karo"],
   "Scammers rush you so you cannot verify."],
  ["Crypto / investment doubling", 35, ["double your money","double profit","guaranteed return","crypto invest","bitcoin double","100% profit","daily profit"],
   "Guaranteed high returns do not exist."],
  ["Task / job scam", 30, ["like and earn","part time job","work from home earn","telegram task","rate hotels earn","per day earn","join telegram"],
   "'Like and earn' jobs that later ask for deposits are task scams."],
  ["Refund / cashback bait", 20, ["refund pending","cashback milega","refund click","payment failed refund"],
   "Refunds never need a link click or a fee."],
  ["Payment demand", 20, ["pay rs","pay ₹","send money","transfer money","processing fee pay","customs fee","delivery charge pay karo"],
   "Paying a fee to receive a prize/parcel/job = advance-fee scam."],
  ["Authority impersonation", 20, ["i am calling from bank","rbi officer","police station","cbi","customs department","income tax department"],
   "Officers do not threaten or collect money like this."],
  ["Digital arrest", 40, ["digital arrest","arrest warrant","money laundering case","video call par raho","do not disconnect"],
   "'Digital arrest' does not exist in law. It is a fear scam."],
];
const LINK_SIGNALS = ["http://","https://","bit.ly","tinyurl",".xyz",".top",".click","wa.me/"];

function analyzeMessage(text) {
  const m = text.toLowerCase();
  const findings = [];
  let score = 0;
  for (const [cat, pts, phrases, why] of MESSAGE_RULES) {
    const hit = phrases.find(p => m.includes(p));
    if (hit) { score += pts; findings.push(`[+${pts}] ${cat}: matched "${hit}" -> ${why}`); }
  }
  const link = LINK_SIGNALS.find(s => m.includes(s));
  if (link) { score += 15; findings.push(`[+15] Link signal: "${link}" in an unsolicited message.`); }
  score = Math.min(100, score);
  const verdict = score >= 60 ? "SCAM / HIGH RISK" : score >= 30 ? "SUSPICIOUS" : "LIKELY SAFE";
  return { score, verdict, findings };
}

if (typeof module !== "undefined") module.exports = { analyzeUrl, analyzeMessage };
