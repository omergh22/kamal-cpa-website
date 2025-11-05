from flask import Flask, render_template, request, redirect, url_for, flash, abort
from pathlib import Path
import csv
import smtplib
import ssl
from email.mime.text import MIMEText
import time
from collections import deque
import os
from dotenv import load_dotenv

# ===== טעינת .env =====
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "secret-for-flash")

# ===== הגדרות מייל (ניתן לכבות דרך .env) =====
SEND_MAIL = os.getenv("SEND_MAIL", "true").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))  # מומלץ: 465 (SSL)
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")              # סיסמת *אפליקציה* של גוגל (16 תווים)
TO_EMAIL  = os.getenv("TO_EMAIL")
FROM_NAME = os.getenv("FROM_NAME", "ליד חדש מהאתר")
SUBJECT_TMPL = os.getenv("SUBJECT", "{name} — ליד חדש מהטופס באתר")

MISSING_SMTP = SEND_MAIL and (not SMTP_USER or not SMTP_PASS or not TO_EMAIL)

# ===== Rate-limit בסיסי ל-/submit =====
RATE_LIMIT_WINDOW_SEC = 15 * 60
RATE_LIMIT_MAX = 5
_ip_hits: dict[str, deque] = {}

def _rate_limited(ip: str) -> bool:
    now = time.time()
    dq = _ip_hits.setdefault(ip, deque())
    while dq and (now - dq[0] > RATE_LIMIT_WINDOW_SEC):
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return True
    dq.append(now)
    return False

# ===== כותרות אבטחה בסיסיות =====
@app.after_request
def security_headers(resp):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    return resp


# ===== תבנית HTML של המייל — כמו בגרסה הישנה (תוויות מימין, ערכים משמאל, בלי IP) =====
def build_email_html(full_name: str, phone_raw: str, email: str, note: str) -> str:
    return f"""
    <div dir="rtl" style="background:#f4f6fb;padding:22px;font-family:Arial,Helvetica,sans-serif">
      <table align="center" style="max-width:880px;width:100%;background:#ffffff;border-radius:10px;overflow:hidden;border-collapse:collapse;box-shadow:0 10px 26px rgba(11,18,34,.10)">
        <tr>
          <td colspan="2" style="background:#0c1324;color:#fff;padding:18px 22px;font-size:20px;font-weight:700;text-align:center">
            ליד חדש התקבל
          </td>
        </tr>

        <!-- שם מלא -->
        <tr style="border-bottom:1px solid #edf1f7">
          <td style="padding:16px 12px;text-align:right;font-weight:700;color:#0e1830;width:120px;white-space:nowrap">שם מלא:</td>
          <td style="padding:16px 18px;text-align:right">{full_name}</td>
        </tr>

        <!-- טלפון -->
        <tr style="border-bottom:1px solid #edf1f7;background:#fafcff">
          <td style="padding:16px 12px;text-align:right;font-weight:700;color:#0e1830;width:120px;white-space:nowrap">טלפון:</td>
          <td style="padding:16px 18px;text-align:right" dir="ltr">{phone_raw}</td>
        </tr>

        <!-- אימייל -->
        <tr style="border-bottom:1px solid #edf1f7">
          <td style="padding:16px 12px;text-align:right;font-weight:700;color:#0e1830;width:120px;white-space:nowrap">אימייל:</td>
          <td style="padding:16px 18px;text-align:right">{email or "-"}</td>
        </tr>

        <!-- הודעה -->
        <tr>
          <td style="padding:16px 12px;text-align:right;font-weight:700;color:#0e1830;width:120px;white-space:nowrap">הודעה:</td>
          <td style="padding:16px 18px;text-align:right">{(note or "—").replace(chr(10), "<br>")}</td>
        </tr>

        <tr>
          <td colspan="2" style="background:#f2f3f6;padding:12px 18px;color:#7b8190;font-size:12px;text-align:center">
            נשלח אוטומטית מהאתר — נא לא להשיב ישירות אם לא דרוש.
          </td>
        </tr>
      </table>
    </div>
    """


# ===== דפים =====
@app.get("/")
def home():
    return render_template("index.html", message=None)


@app.post("/submit")
def submit():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()
    if _rate_limited(client_ip):
        return render_template("index.html", message="ביצעת יותר מדי שליחות בזמן קצר. נסה/י שוב בעוד מספר דקות.")

    full_name = request.form.get("full_name", "").strip()
    phone_raw = request.form.get("phone", "").strip()
    email     = request.form.get("email", "").strip()
    note      = request.form.get("message", "").strip()
    honeypot  = request.form.get("company", "").strip()  # שדה חבוי לאיתור בוטים

    if honeypot:
        return redirect(url_for("home") + "#contact")

    phone_digits = "".join(ch for ch in phone_raw if ch.isdigit())
    if not full_name or not phone_digits:
        return render_template("index.html", message="אנא מלא/י שם מלא וטלפון.")
    if len(phone_digits) < 8:
        return render_template("index.html", message="מספר הטלפון אינו תקין.")

    # שמירה ל-CSV
    out = Path("leads.csv")
    new = not out.exists()
    with out.open("a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["full_name", "phone_digits", "phone_raw", "email", "message", "ip"])
        w.writerow([full_name, phone_digits, phone_raw, email, note, client_ip])

    # שליחת מייל
    if SEND_MAIL:
        if MISSING_SMTP:
            print("⚠️  SMTP settings missing (SMTP_USER/SMTP_PASS/TO_EMAIL). Email not sent.")
            flash("הפרטים נקלטו, אך הגדרות המייל חסרות. אפשר ליצור קשר גם בטלפון 054-5540446.")
            return redirect(url_for("home") + "#contact")

        subject_line = SUBJECT_TMPL.format(name=full_name)
        body = build_email_html(full_name, phone_raw, email, note)

        msg = MIMEText(body, "html", "utf-8")
        msg["Subject"] = subject_line
        msg["From"] = f"{FROM_NAME} <{SMTP_USER}>"
        msg["To"] = TO_EMAIL

        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ssl.create_default_context()) as s:
                    s.login(SMTP_USER, SMTP_PASS)
                    s.sendmail(SMTP_USER, [TO_EMAIL], msg.as_string())
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                    s.ehlo()
                    s.starttls(context=ssl.create_default_context())
                    s.login(SMTP_USER, SMTP_PASS)
                    s.sendmail(SMTP_USER, [TO_EMAIL], msg.as_string())
        except Exception as e:
            print(f"✉️  Email send failed: {e!r}")
            flash("הפרטים נקלטו, אך שליחת המייל נכשלה. אפשר להתקשר 054-5540446.")
            return redirect(url_for("home") + "#contact")

    flash("תודה! הפרטים נקלטו ונחזור אליך בהקדם.")
    return redirect(url_for("home") + "#contact")


# ===== נתוני השירותים =====
SERVICES = {
    "tax-refund": {
        "title": "החזרי מס",
        "intro": "הרבה מאוד שכירים ועצמאים בישראל משלמים מס הכנסה גבוה יותר ממה שהם באמת חייבים לשלם – ולא מודעים לכך שמגיע להם החזר כספי ישירות לחשבון הבנק. במשרדנו, בהובלת רו\"ח כמאל סרחאן, אנחנו דואגים לבדוק עבורך האם שילמת מס עודף ומטפלים בכל התהליך מול מס הכנסה בצורה מקצועית, מהירה וללא כאב ראש.",
        "hero_img": "hehzer-mas.png",
        "sections": [
            {
                "heading": "למי מגיע החזר מס",
                "bullets": [
                    "✔ שכירים ששילמו מס גבוה מדי במהלך השנים",
                    "✔ מי שהחליף מקום עבודה או היו לו תקופות אבטלה",
                    "✔ סטודנטים שסיימו תואר ראשון",
                    "✔ הורים לילדים (ובמיוחד ילדים עם מוגבלות)",
                    "✔ חיילים משוחררים",
                    "✔ מי שמשך כספים מקרנות פנסיה / השתלמות",
                    "✔ עצמאים ששילמו מקדמות גבוהות מהנדרש",
                    "✔ כל מי שעבר שינוי במצב המשפחתי – נישואין, גירושין, לידה ועוד",
                ],
            },
            {
                "heading": "למה לבחור בנו",
                "bullets": [
                    "✅ בדיקה מקיפה ומקצועית של כל הזכויות שלך",
                    "✅ טיפול מלא מול רשויות המס – עד לקבלת ההחזר בפועל",
                    "✅ שקיפות מלאה לאורך כל הדרך",
                    "✅ ניסיון רב שנים ולקוחות מרוצים שכבר קיבלו החזרים של אלפי שקלים",
                ],
            },
        ],
        "cta": "📞 זה הזמן לבדוק אם גם לך מגיע כסף חזרה מהמדינה!<br>השאר פרטים עכשיו ואנחנו נדאג להחזיר לך את מה שמגיע לך.",
    },
    "audit": {
        "title": "ביקורת חברות – הדרך שלך לניהול נכון, בטוח ושקוף",
        "intro": "ביקורת דוחות כספיים היא לא רק דרישה של החוק – היא הכלי שלך כבעל עסק להבין את מצב החברה בצורה אמינה, לקבל החלטות נכונות וליצור אמון מול בנקים, משקיעים ורשויות המס.",
        "hero_img": "bekoret-dohot.png",
        "sections": [
            { "paragraph": "במשרדנו, בהובלת רו\"ח כמאל סרחאן, אנו מבצעים ביקורת חברות ברמה הגבוהה ביותר תוך הקפדה על שקיפות, אמינות ושירות אישי." },
            {
                "heading": "למה בכלל צריך ביקורת חברות",
                "bullets": [
                    "✔ עמידה בדרישות החוק ומס הכנסה",
                    "✔ הצגת תמונת מצב אמיתית של החברה",
                    "✔ חיזוק האמינות מול בנקים, ספקים ומשקיעים",
                    "✔ איתור טעויות או בעיות כספיות בזמן – לפני שהן הופכות לבעיה גדולה",
                    "✔ תכנון מס נכון וחיסכון בהוצאות מיותרות",
                ],
            },
            {
                "heading": "למה לבחור בנו",
                "bullets": [
                    "✅ ניסיון מקצועי רב בביקורת דוחות כספיים לחברות במגוון תחומים",
                    "✅ ליווי אישי וצמוד – זמינים עבורך לכל שאלה",
                    "✅ הקפדה על מקצועיות, שקיפות ודקדקנות בכל פרט",
                    "✅ שילוב בין ידע חשבונאי עמוק לבין הבנה עסקית רחבה",
                    "✅ דוחות ברורים ומדויקים שיעזרו לך לנהל את החברה בביטחון",
                ],
            },
        ],
        "cta": "📞 החברה שלך צריכה ביקורת מקצועית?<br>השאר פרטים עכשיו ונשמח ללוות אותך בדרך לניהול פיננסי חכם ובטוח.",
    },
    "bookkeeping": {
        "title": "הנהלת חשבונות – הסדר הפיננסי שהעסק שלך חייב",
        "intro": "ניהול נכון של הנהלת החשבונות הוא הלב הפועם של כל עסק. כשיש סדר, מעקב ובקרה – העסק שלך יכול לצמוח בראש שקט, בלי הפתעות מול רשויות המס ובלי כאב ראש מיותר.",
        "hero_img": "hanhalat-heshbonot.png",
        "sections": [
            { "paragraph": "במשרדנו, בהובלת רו\"ח כמאל סרחאן, אנו מציעים שירותי הנהלת חשבונות מותאמים אישית לעסקים קטנים, בינוניים וחברות – עם דגש על מקצועיות, אמינות ושקיפות מלאה." },
            {
                "heading": "מה כוללים שירותי הנהלת החשבונות שלנו",
                "bullets": [
                    "✔ רישום ותיעוד שוטף של כל הפעולות הכספיות",
                    "✔ הפקת דוחות חודשיים ושנתיים לניהול ובקרה",
                    "✔ טיפול בדיווחים לרשויות המס וביטוח לאומי",
                    "✔ הכנת משכורות ודוחות עובדים",
                    "✔ ייעוץ וליווי פיננסי שוטף להתנהלות נכונה",
                ],
            },
            {
                "heading": "למה לבחור בנו",
                "bullets": [
                    "✅ חיסכון בזמן – אנחנו דואגים לכל הניירת עבורך",
                    "✅ ראש שקט מול רשויות המס – עמידה מלאה בכל הדרישות",
                    "✅ שירות אישי וליווי צמוד – זמינות מלאה עבורך",
                    "✅ דוחות מסודרים וברורים שיתנו לך שליטה מלאה על העסק",
                    "✅ ידע וניסיון עם עסקים מכל התחומים",
                ],
            },
        ],
        "cta": "📞 הגיע הזמן לשים את הכספים שלך בידיים מקצועיות!<br>השאר פרטים עכשיו ותוכל להתמקד בניהול העסק – אנחנו נדאג לחשבונות.",
    },
    "biz-loans": {
        "title": "ייעוץ עסקי והלוואות בערבות מדינה – הצעד החכם לצמיחה של העסק שלך",
        "intro": "עסק מצליח זקוק לשילוב של ניהול נכון ומקורות מימון מתאימים. אנחנו כאן כדי לעזור לך לתכנן, להתייעל, ולקבל את המימון הדרוש לך להגשמת היעדים העסקיים שלך – בקלות ובמקצועיות.",
        "hero_img": "yaots-aeske.png",
        "sections": [
            { "paragraph": "במשרדנו, בהובלת רו\"ח כמאל סרחאן, אנו מציעים שירותי ייעוץ עסקי מקיף יחד עם ליווי לקבלת הלוואות בערבות מדינה – פתרון מימון נוח ובטוח לעסקים קטנים ובינוניים." },
            {
                "heading": "מה כולל השירות שלנו",
                "bullets": [
                    "✔ ייעוץ עסקי מותאם אישית – ניתוח מצב העסק והגדרת יעדים",
                    "✔ בניית תוכנית עסקית מקצועית וברורה",
                    "✔ ליווי מלא בהגשת בקשות להלוואות בערבות מדינה",
                    "✔ בדיקה והשוואה של מסלולי מימון קיימים",
                    "✔ מו\"מ מול בנקים וגופים פיננסיים להשגת תנאים מיטביים",
                ],
            },
            {
                "heading": "למה דווקא הלוואות בערבות מדינה",
                "bullets": [
                    "💡 תנאי מימון נוחים במיוחד לעסקים קטנים ובינוניים",
                    "💡 ריביות נמוכות יותר מהמקובל בשוק",
                    "💡 אפשרות לפריסה ארוכה ונוחה של ההחזרים",
                    "💡 מימון שיכול לעזור בצמיחה, בהתרחבות, או ביציאה מתקופות מאתגרות",
                ],
            },
            {
                "heading": "למה לבחור בנו",
                "bullets": [
                    "✅ ניסיון מוכח בליווי עסקים מול הבנקים ומרכזי ההשקעות",
                    "✅ בניית תוכנית עסקית אמיתית שתשרת אותך גם לטווח הארוך",
                    "✅ יחס אישי – אנחנו איתך יד ביד עד לקבלת ההלוואה",
                    "✅ שילוב בין ידע חשבונאי, עסקי ופיננסי שמייצר תוצאות",
                ],
            },
        ],
        "cta": "📞 רוצה לקחת את העסק שלך צעד קדימה?<br>השאר פרטים עכשיו ונבדוק יחד איך אפשר להשיג עבורך את ההלוואה בתנאים הכי טובים – עם ליווי מקצועי ואמין לכל הדרך.",
    },
    "open-files": {
        "title": "פתיחת תיקים ברשויות המס – פותחים עסק בראש שקט",
        "intro": "רוצה להתחיל לעבוד כעצמאי או להקים חברה? הצעד הראשון הוא פתיחת תיקים במס הכנסה, מע\"מ וביטוח לאומי.",
        "hero_img": "ptehat-tekem.png",
        "sections": [
            { "paragraph": "הבעיה? התהליך מורכב, מלא טפסים ושאלות – וכל טעות קטנה עלולה לעלות ביוקר בהמשך." },
            {
                "heading": "איזה תיקים אנחנו פותחים עבורך",
                "bullets": [
                    "✔ עוסק פטור – מתאים לעסקים קטנים בתחילת הדרך",
                    "✔ עוסק מורשה – לעסקים בצמיחה או כאלה עם מחזור גבוה יותר",
                    "✔ חברה בע\"מ – כולל רישום ברשם החברות, מס הכנסה, מע\"מ וביטוח לאומי",
                ],
            },
            {
                "heading": "למה חשוב לפתוח את התיקים בצורה נכונה",
                "bullets": [
                    "💡 עמידה בדרישות החוק מהרגע הראשון",
                    "💡 מניעת טעויות שעלולות לגרום לקנסות או חובות מיותרים",
                    "💡 התאמת סוג התיק לאופי העסק – כדי לשלם פחות מס",
                    "💡 חיסכון בזמן והתעסקות בניירת",
                ],
            },
            {
                "heading": "למה לבחור בנו",
                "bullets": [
                    "✅ טיפול מקיף מול כל הרשויות – אתה לא צריך לרדוף אחרי אף אחד",
                    "✅ ייעוץ והכוונה איזה סוג תיק מתאים לעסק שלך (פטור, מורשה או חברה)",
                    "✅ שקיפות מלאה וליווי אישי לאורך כל הדרך",
                    "✅ התחלה חלקה ונכונה שתאפשר לך להתמקד במה שחשוב – לפתח את העסק שלך",
                ],
            },
        ],
        "cta": "📞 פותח עסק חדש? אל תתמודד עם זה לבד!<br>השאר פרטים עכשיו ונשמח ללוות אותך בפתיחת התיקים מול כל הרשויות – בקלות ובמקצועיות.",
    },
    "mortgage": {
        "title": "ייעוץ משכנתא – הדרך החכמה לבית משלך",
        "intro": "משכנתא היא העסקה הגדולה ביותר שתעשה בחיים – והיא עלולה לעלות לך מאות אלפי שקלים יותר אם לא תתנהל נכון.",
        "hero_img": "yeaots-meshkanta.png",
        "sections": [
            { "paragraph": "אנחנו כאן כדי לוודא שאתה מקבל את המשכנתא המתאימה ביותר לצרכים שלך ובתנאים המשתלמים ביותר." },
            { "paragraph": "במשרדנו, בהובלת רו\"ח כמאל סרחאן, אנו מלווים אותך אישית בכל שלבי תהליך המשכנתא – מהבדיקה הראשונית ועד לחתימה מול הבנק." },
            {
                "heading": "מה כולל השירות שלנו",
                "bullets": [
                    "✔ בדיקה מקיפה של הצרכים והיכולות הפיננסיות שלך",
                    "✔ השוואה בין מסלולי משכנתא בבנקים שונים",
                    "✔ מו\"מ עם הבנקים להשגת תנאים טובים יותר",
                    "✔ ליווי אישי עד החתימה וקבלת הכסף",
                    "✔ ייעוץ גם למחזור משכנתא קיימת – כדי לחסוך אלפי שקלים",
                ],
            },
            {
                "heading": "למה לבחור בנו",
                "bullets": [
                    "✅ חיסכון משמעותי בריביות ובתנאי המשכנתא",
                    "✅ שירות אישי, שקוף ומותאם בדיוק עבורך",
                    "✅ ניסיון רב במו\"מ מול כל הבנקים",
                    "✅ ידע חשבונאי ופיננסי שמעניק לך יתרון אמיתי",
                    "✅ ליווי צמוד עד הסוף – אתה לא לבד בתהליך",
                ],
            },
        ],
        "cta": "📞 חולם על בית חדש? או רוצה לחסוך במשכנתא קיימת?<br>השאר פרטים עכשיו ונמצא עבורך את המשכנתא המשתלמת ביותר – בדרך בטוחה ושקופה.",
    },
}

@app.get("/service/<slug>")
def service(slug):
    page = SERVICES.get(slug)
    if not page:
        abort(404)
    return render_template("service.html", page=page)


if __name__ == "__main__":
    app.run(debug=False)
