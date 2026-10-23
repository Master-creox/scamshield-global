import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * ScamShield Global - Java Scam Message Analyzer (message layer)
 *
 * Scores SMS / WhatsApp / email text for scam patterns used worldwide:
 * urgency pressure, prize & lottery bait, KYC / account-block threats,
 * OTP & PIN requests, crypto doubling, task/job scams, refund bait and
 * malicious-link signals. Every point is explained - no black box.
 *
 * Run:  javac ScamMessageAnalyzer.java && java ScamMessageAnalyzer
 *       java ScamMessageAnalyzer "your message here"
 */
public class ScamMessageAnalyzer {

    static class Rule {
        final String category; final int points; final String[] phrases; final String why;
        Rule(String c, int p, String[] ph, String w) { category = c; points = p; phrases = ph; why = w; }
    }

    static final Rule[] RULES = {
        new Rule("OTP / PIN request", 45,
            new String[]{"share your otp", "send otp", "otp batao", "share the otp", "enter your pin",
                         "share your pin", "cvv", "card number batao", "send the code sent"},
            "Banks and real companies NEVER ask for OTP, PIN or CVV. Asking for it = scam, always."),
        new Rule("Prize / lottery bait", 30,
            new String[]{"you have won", "you won", "lottery", "lucky draw", "prize", "crore",
                         "lakh win", "winner selected", "claim your reward", "jackpot"},
            "Unexpected prizes that you never entered are the oldest scam bait in the world."),
        new Rule("KYC / account-block threat", 30,
            new String[]{"kyc", "account will be blocked", "account blocked", "suspended within",
                         "verify your account", "pan card update", "aadhaar update", "sim will be blocked",
                         "connection will be cut", "bijli kat jayegi"},
            "Threatening to block your account/bill unless you act NOW is a pressure tactic, not real policy."),
        new Rule("Urgency pressure", 15,
            new String[]{"urgent", "immediately", "within 24 hours", "within 2 hours", "last chance",
                         "act now", "expires today", "turant", "abhi karo"},
            "Scammers rush you so you cannot think or verify. Real institutions give you time."),
        new Rule("Crypto / investment doubling", 35,
            new String[]{"double your money", "double profit", "guaranteed return", "crypto invest",
                         "bitcoin double", "100% profit", "daily profit", "investment plan join"},
            "Guaranteed high returns do not exist. 'Double money' schemes always end with your money gone."),
        new Rule("Task / job scam", 30,
            new String[]{"like and earn", "part time job", "work from home earn", "telegram task",
                         "rate hotels earn", "per day earn", "join telegram", "task complete karke"},
            "'Like videos / rate hotels and earn' jobs that later ask for deposits are task scams."),
        new Rule("Refund / cashback bait", 20,
            new String[]{"refund pending", "cashback milega", "refund click", "payment failed refund"},
            "Refunds never need you to click a link or pay a 'processing fee'."),
        new Rule("Payment demand", 20,
            new String[]{"pay rs", "pay ₹", "send money", "transfer money", "processing fee pay",
                         "customs fee", "delivery charge pay karo"},
            "Being asked to pay a fee to receive a prize, parcel or job is a classic advance-fee scam."),
        new Rule("Authority impersonation", 20,
            new String[]{"i am calling from bank", "rbi officer", "police station", "cbi", "customs department",
                         "income tax department", "bank manager bol raha"},
            "Officers and banks do not threaten or collect money over calls/messages like this."),
        new Rule("Digital arrest", 40,
            new String[]{"digital arrest", "arrest warrant", "money laundering case", "video call par raho",
                         "do not disconnect"},
            "'Digital arrest' does not exist in law. It is a fear scam run on video calls."),
    };

    static final String[] LINK_SIGNALS = {"http://", "https://", "bit.ly", "tinyurl", ".xyz", ".top", ".click", "wa.me/"};

    static class Result {
        int score; List<String> findings = new ArrayList<>();
        String verdict() { return score >= 60 ? "SCAM / HIGH RISK" : score >= 30 ? "SUSPICIOUS" : "LIKELY SAFE"; }
    }

    static Result analyze(String message) {
        String m = message.toLowerCase(Locale.ROOT);
        Result r = new Result();
        for (Rule rule : RULES) {
            for (String ph : rule.phrases) {
                if (m.contains(ph)) {
                    r.score += rule.points;
                    r.findings.add("[+" + rule.points + "] " + rule.category + ": matched \"" + ph + "\"\n      -> " + rule.why);
                    break; // one hit per category
                }
            }
        }
        for (String s : LINK_SIGNALS) {
            if (m.contains(s)) { r.score += 15; r.findings.add("[+15] Link signal: message contains \"" + s + "\" - links in unsolicited messages are a top scam carrier."); break; }
        }
        if (r.score > 100) r.score = 100;
        return r;
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            printResult(String.join(" ", args));
            return;
        }
        String[][] tests = {
            {"SCAM", "Congratulations! You have won Rs 25,00,000 in lucky draw lottery. Claim your reward now, pay Rs 499 processing fee pay karo: http://claim-prize.xyz"},
            {"SCAM", "Dear customer your bank account will be blocked today. KYC update immediately, share your OTP sent to your mobile."},
            {"SCAM", "Digital arrest warrant issued in money laundering case. Do not disconnect the video call. - CBI officer"},
            {"SCAM", "Part time job: like and earn Rs 3000 per day. Join Telegram task group and complete tasks."},
            {"SCAM", "Invest in crypto invest plan, double your money in 30 days, guaranteed return 100% profit."},
            {"LEGIT", "Your OTP for login is 483920. Do not share it with anyone. - Bank"},
            {"LEGIT", "Hi, your parcel will be delivered tomorrow between 10 AM and 2 PM. Track in the app."},
            {"LEGIT", "Reminder: your electricity bill of Rs 1,240 is due on 28 Oct. Pay via the official app."},
            {"LEGIT", "Team meeting moved to 4 PM today. Please bring the quarterly report."},
            {"LEGIT", "Your salary of Rs 45,000 has been credited to your account ending 2211."},
        };
        int correct = 0;
        for (String[] t : tests) {
            Result r = analyze(t[1]);
            boolean scam = r.score >= 30;
            boolean ok = scam == t[0].equals("SCAM");
            if (ok) correct++;
            System.out.println((ok ? "[OK]   " : "[MISS] ") + "expected=" + t[0] + " score=" + r.score + " (" + r.verdict() + ")");
        }
        System.out.println("\n=== MESSAGE ANALYZER EVALUATION ===");
        System.out.println("Total: " + tests.length + "  Correct: " + correct + "  Accuracy: " + (100.0 * correct / tests.length) + "%");
        System.out.println("\n--- Example detailed report ---");
        printResult(tests[1][1]);
    }

    static void printResult(String message) {
        Result r = analyze(message);
        System.out.println("Message: \"" + message + "\"");
        System.out.println("Risk score: " + r.score + "/100 -> " + r.verdict());
        for (String f : r.findings) System.out.println("  " + f);
        if (r.findings.isEmpty()) System.out.println("  No scam patterns matched.");
    }
}
