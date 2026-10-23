// ScamShield Global - C++ URL Risk Engine (high-performance layer)
// Analyzes a URL and returns a 0-100 risk score with explainable reasons.
// Layers: blocklist -> official-domain check -> typosquat (Levenshtein)
//         -> structural heuristics (IP host, '@' trick, punycode, TLD, keywords)
#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

static std::string lower(std::string s){ for(char&c:s) c=std::tolower((unsigned char)c); return s; }
static std::string trim(const std::string& s){ size_t a=s.find_first_not_of(" \t\r\n"); if(a==std::string::npos) return ""; size_t b=s.find_last_not_of(" \t\r\n"); return s.substr(a,b-a+1); }
static int lev(const std::string& a, const std::string& b){
    std::vector<int> prev(b.size()+1), cur(b.size()+1);
    for(size_t j=0;j<=b.size();j++) prev[j]=(int)j;
    for(size_t i=1;i<=a.size();i++){ cur[0]=(int)i;
        for(size_t j=1;j<=b.size();j++) cur[j]=std::min({prev[j]+1, cur[j-1]+1, prev[j-1]+(a[i-1]==b[j-1]?0:1)});
        prev.swap(cur); }
    return prev[b.size()];
}
static std::vector<std::string> split(const std::string& s, char d){
    std::vector<std::string> out; std::string cur;
    for(char c: s){ if(c==d){ out.push_back(cur); cur.clear(); } else cur+=c; }
    out.push_back(cur); return out;
}

struct Brand { std::string name; std::string domain; };

static std::string hostOf(const std::string& url){
    std::string u = lower(url);
    size_t p = u.find("://"); if(p!=std::string::npos) u = u.substr(p+3);
    size_t end = u.find_first_of("/?#"); if(end!=std::string::npos) u = u.substr(0,end);
    size_t at = u.rfind('@'); if(at!=std::string::npos) u = u.substr(at+1); // strip userinfo trick for host view
    size_t colon = u.find(':'); if(colon!=std::string::npos) u = u.substr(0,colon);
    return u;
}
static bool isIP(const std::string& h){
    auto parts = split(h,'.'); if(parts.size()!=4) return false;
    for(auto& p: parts){ if(p.empty()||p.size()>3) return false; for(char c:p) if(!std::isdigit((unsigned char)c)) return false; }
    return true;
}
static std::string registrable(const std::string& host){
    auto parts = split(host,'.');
    if(parts.size()<=2) return host;
    // crude handling for co.in / com.br style second-level TLDs
    const std::unordered_set<std::string> two = {"co","com","net","org","ac","gov"};
    if(parts.size()>=3 && two.count(parts[parts.size()-2]) && parts.back().size()==2)
        return parts[parts.size()-3]+"."+parts[parts.size()-2]+"."+parts.back();
    return parts[parts.size()-2]+"."+parts.back();
}
static std::string brandStem(const std::string& reg){
    auto parts = split(reg,'.'); return parts.empty()? reg : parts[0];
}

struct Result { int score; std::string verdict; std::vector<std::string> reasons; };

static Result analyze(const std::string& url,
                      const std::unordered_set<std::string>& blocklist,
                      const std::vector<Brand>& brands){
    Result r{0,"",{}};
    std::string u = lower(url);
    std::string host = hostOf(url);
    std::string reg = registrable(host);
    auto add = [&](int pts, const std::string& why){ r.score += pts; r.reasons.push_back("+" + std::to_string(pts) + " " + why); };

    if(blocklist.count(host) || blocklist.count(reg)){ r.score = 100; r.reasons.push_back("+100 domain is on the known-scam blocklist"); }
    bool official = false;
    for(auto& b: brands) if(reg == b.domain) official = true;
    if(official){ r.reasons.push_back("+0 official domain of a protected brand"); r.verdict = "SAFE";
        if(r.score < 100) r.score = std::min(r.score, 5); return r; }

    // typosquatting: registrable stem (or any '-'-separated token of it) similar
    // to a brand but not the official domain
    std::string stem = brandStem(reg);
    std::vector<std::string> tokens = split(stem, '-');
    bool brandHit = false;
    for(auto& b: brands){
        std::string bstem = brandStem(b.domain);
        if((int)bstem.size() < 4) continue;
        int d = lev(stem, bstem);
        if(stem != bstem && d <= 2){
            add(45, "domain imitates brand '" + b.name + "' (edit distance " + std::to_string(d) + " from " + b.domain + ")");
            brandHit = true; break;
        }
        if(stem.find(bstem) != std::string::npos && stem != bstem){
            add(35, "domain contains brand name '" + b.name + "' but is not " + b.domain);
            brandHit = true; break;
        }
        for(auto& tok: tokens){
            if(tok.size() < 4) continue;
            int td = lev(tok, bstem);
            if(tok != bstem && td <= 2){
                add(45, "domain token '" + tok + "' imitates brand '" + b.name + "' (edit distance " + std::to_string(td) + ")");
                brandHit = true; break;
            }
            if(bstem.find(tok) != std::string::npos && tok != bstem){
                add(35, "domain token '" + tok + "' is part of brand '" + b.name + "' but domain is not " + b.domain);
                brandHit = true; break;
            }
        }
        if(brandHit) break;
    }
    // brand name hidden in the userinfo part (before '@') — classic deception
    {
        std::string noScheme2 = u; size_t pp = u.find("://"); if(pp!=std::string::npos) noScheme2 = u.substr(pp+3);
        size_t at = noScheme2.find('@'); size_t sl = noScheme2.find('/');
        if(at!=std::string::npos && (sl==std::string::npos || at<sl)){
            std::string userinfo = noScheme2.substr(0, at);
            std::string uiStem = userinfo.substr(0, userinfo.find('.'));
            for(auto& b: brands){
                std::string bstem = brandStem(b.domain);
                if(userinfo.find(bstem) != std::string::npos || lev(uiStem, bstem) <= 2){
                    add(35, "brand '" + b.name + "' appears before '@' — the real destination is a different host");
                    break;
                }
            }
        }
    }
    if(u.find("xn--") != std::string::npos) add(20, "punycode domain (homograph-attack technique)");
    if(isIP(host)) add(25, "host is a raw IP address instead of a domain");
    std::string noScheme = u; size_t p = u.find("://"); if(p!=std::string::npos) noScheme = u.substr(p+3);
    if(noScheme.find('@') != std::string::npos && noScheme.find('@') < noScheme.find('/')) add(20, "'@' in URL hides the real destination");
    auto parts = split(host,'.');
    if(parts.size() >= 4) add(15, "many subdomains (" + std::to_string(parts.size()) + ") used to disguise the real domain");
    std::string tld = parts.empty()? "" : parts.back();
    const std::unordered_set<std::string> risky = {"xyz","top","click","buzz","live","club","site","online","fun","icu","work"};
    if(risky.count(tld)) add(10, "high-abuse TLD (." + tld + ")");
    const std::vector<std::string> kw = {"verify","login","secure","bonus","free","claim","prize","wallet","kyc","update","billing","refund","winner"};
    int kwHits = 0; for(auto& k: kw) if(u.find(k)!=std::string::npos) kwHits++;
    if(kwHits) add(std::min(20, kwHits*7), "scam keywords in URL (" + std::to_string(kwHits) + " found)");
    int digits = 0; for(char c: stem) if(std::isdigit((unsigned char)c)) digits++;
    if(digits >= 2) add(10, "digits inside the brand-like name (character substitution)");
    if(url.size() > 75) add(10, "unusually long URL");
    if(u.rfind("http://",0)==0) add(5, "plain HTTP (no encryption)");

    if(r.score >= 60) r.verdict = "SCAM / HIGH RISK";
    else if(r.score >= 30) r.verdict = "SUSPICIOUS";
    else r.verdict = "LIKELY SAFE";
    if(r.score > 100) r.score = 100;
    return r;
}

static bool loadLines(const std::string& path, std::unordered_set<std::string>& set){
    std::ifstream f(path); if(!f) return false; std::string line;
    while(std::getline(f,line)){ line = trim(line); if(!line.empty() && line[0]!='#') set.insert(lower(line)); }
    return true;
}
static bool loadBrands(const std::string& path, std::vector<Brand>& brands){
    std::ifstream f(path); if(!f) return false; std::string line;
    while(std::getline(f,line)){ line = trim(line); if(line.empty()||line[0]=='#') continue;
        std::istringstream ss(line); Brand b; if(ss>>b.name>>b.domain) brands.push_back(b); }
    return true;
}

int main(int argc, char** argv){
    std::string dataDir = "../data";
    for(int i=1;i<argc;i++) if(std::string(argv[i])=="--data" && i+1<argc) dataDir = argv[++i];
    std::unordered_set<std::string> blocklist; std::vector<Brand> brands;
    if(!loadLines(dataDir+"/blocklist.txt", blocklist)) { std::cerr << "cannot load blocklist in " << dataDir << "\n"; return 1; }
    if(!loadBrands(dataDir+"/brands.txt", brands)) { std::cerr << "cannot load brands in " << dataDir << "\n"; return 1; }

    std::string mode = argc>1 ? argv[1] : "";
    if(mode=="check" && argc>2){
        Result r = analyze(argv[2], blocklist, brands);
        std::cout << "URL: " << argv[2] << "\nRisk score: " << r.score << "/100 -> " << r.verdict << "\n";
        for(auto& why: r.reasons) std::cout << "  " << why << "\n";
        return 0;
    }
    if(mode=="batch" && argc>2){
        std::ifstream f(argv[2]); std::string line; int total=0, correct=0, tp=0, fp=0, fn=0;
        std::getline(f,line); // header
        while(std::getline(f,line)){ line=trim(line); if(line.empty()) continue;
            auto c = line.rfind(','); std::string url = line.substr(0,c), label = line.substr(c+1);
            Result r = analyze(url, blocklist, brands);
            bool scam = r.score >= 30; bool actual = (label=="scam");
            total++; if(scam==actual) correct++;
            if(scam&&actual) tp++; if(scam&&!actual) fp++; if(!scam&&actual) fn++;
            std::cout << (scam==actual?"[OK]  ":"[MISS]") << " " << url << " -> " << r.score << " (" << r.verdict << ")\n";
        }
        std::cout << "\n=== EVALUATION ===\nTotal: " << total << "  Correct: " << correct
                  << "  Accuracy: " << (total? (100.0*correct/total):0) << "%\n"
                  << "True positives: " << tp << "  False positives: " << fp << "  False negatives: " << fn << "\n";
        return 0;
    }
    std::cout << "ScamShield C++ URL Risk Engine\nUsage:\n  scam_engine [--data DIR] check <url>\n  scam_engine [--data DIR] batch <test_urls.csv>\n";
    return 0;
}
