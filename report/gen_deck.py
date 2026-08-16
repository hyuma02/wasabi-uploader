# -*- coding: utf-8 -*-
# 現状レポート（データ保護）: コンサル調スライドPDF生成
# 毎週日曜、WEEKS の先頭に新しい週のエントリを追加して再生成する。
# 実行: python3 report/gen_deck.py  →  report/現状レポート.pdf
# 依存: pip install reportlab（フォントは IPAGothic を使用）
import os
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import stringWidth

# ======================================================================
# 週次ピックアップ（新しい週を先頭に追加する）
# picks: (タイトル, 使いどころ, キー数字・出典)
# ======================================================================
WEEKS = [
    {
        "period": "2026年8月8日〜8月16日",
        "no": 1,
        "summary": "初週にして「掴み→課題→今やる理由→コスト正当化」のプレゼン一式が揃った週。",
        "picks": [
            ("警察庁統計：バックアップがあっても約8割が復旧できず",
             "課題提起の決め札。国の公式統計で「“無事に残っているか”が勝負」と語れる",
             "取得約9割・復旧約2割・67%はバックアップも暗号化 ｜ 警察庁（DB 8/10）"),
            ("アサヒGHD、ランサム被害で営業利益 約370億円弱の減益",
             "経営層向けの掴み。損失の正体は身代金ではなく事業停止＋復旧コスト",
             "供給停止 約200億円＋復旧費 約170億円・完全復旧まで約7か月（DB 8/14）"),
            ("IPA「情報セキュリティ5か条」にバックアップ追加、6か条に",
             "「今やる理由」。国の基本指針に格上げ＋SCS評価制度で取引要件化の流れ",
             "ガイドライン第4.0版（2026年3月）｜ IPA・経産省（DB 8/14）"),
            ("Wasabi Index 日本版：支出の51%がデータ利用Fee",
             "コスト差別化。日本市場の一次データでエグレス無料・定額の優位を訴求",
             "支出の51%がFee・49%が予算超過 ｜ Wasabi Japan（DB 8/8）"),
            ("Sophos 2026：バックアップ復旧66%に上昇、身代金支払い48%に低下",
             "解決編のポジティブ材料。「確実に戻せる備え＝身代金を拒む交渉力」",
             "復旧66%（+12pt）・支払い48%・要求額中央値-65% ｜ Sophos（DB 8/12）"),
        ],
        "note": "補欠: 削除型ランサム事例（S3バケット45件削除・8/13）／Halcyon 侵入6.6万円vs復旧2.3億円（8/11）",
    },
]

FONT_PATH = "/usr/share/fonts/opentype/ipafont-gothic/ipag.ttf"
if not os.path.exists(FONT_PATH):
    FONT_PATH = "/usr/share/fonts/truetype/fonts-japanese-gothic.ttf"
pdfmetrics.registerFont(TTFont("JP", FONT_PATH))
FONT = "JP"

PRIMARY = HexColor("#1F6FB2"); DARK = HexColor("#16324A"); MID = HexColor("#2F80C4")
LIGHT = HexColor("#DCEBF7"); BORDER = HexColor("#9CC3E5"); MUTED = HexColor("#7A93A8")
RULE = HexColor("#C9D8E4"); WHITE = HexColor("#FFFFFF"); ACCENT = HexColor("#0E4D80")

IN = 72.0
PW, PH = 13.333 * IN, 7.5 * IN
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "現状レポート.pdf")
c = canvas.Canvas(OUT, pagesize=(PW, PH))
TOTAL = 4 + len(WEEKS)  # 本編ページ数（表紙除く）

def X(v): return v * IN
def Yt(v): return PH - v * IN

def rect(x, y, w, h, fill=None, stroke=None, lw=1):
    if fill is not None: c.setFillColor(fill)
    if stroke is not None: c.setStrokeColor(stroke); c.setLineWidth(lw)
    c.rect(X(x), Yt(y + h), X(w), X(h), stroke=1 if stroke is not None else 0, fill=1 if fill is not None else 0)

def rrect(x, y, w, h, fill=None, stroke=None, lw=1, r=0.06):
    if fill is not None: c.setFillColor(fill)
    if stroke is not None: c.setStrokeColor(stroke); c.setLineWidth(lw)
    c.roundRect(X(x), Yt(y + h), X(w), X(h), X(r), stroke=1 if stroke is not None else 0, fill=1 if fill is not None else 0)

def hline(x1, x2, y, color=RULE, lw=0.8):
    c.setStrokeColor(color); c.setLineWidth(lw)
    c.line(X(x1), Yt(y), X(x2), Yt(y))

def circle(cx, cy, rad, fill=None, stroke=None, lw=1):
    if fill is not None: c.setFillColor(fill)
    if stroke is not None: c.setStrokeColor(stroke); c.setLineWidth(lw)
    c.circle(X(cx), Yt(cy), X(rad), stroke=1 if stroke is not None else 0, fill=1 if fill is not None else 0)

def text(x, y_top, s, size, color, align="left", bold=False, box_w=None, cs=0):
    c.setFillColor(color)
    baseline = Yt(y_top) - size * 0.82
    w = stringWidth(s, FONT, size) + cs * max(0, len(s) - 1)
    xp = X(x)
    if align == "center":
        xp = X(x) + (X(box_w) - w) / 2.0 if box_w else X(x) - w / 2.0
    elif align == "right":
        xp = X(x) + X(box_w) - w if box_w else X(x) - w
    def _draw(mode):
        t = c.beginText(xp, baseline); t.setTextRenderMode(mode)
        if cs: t.setCharSpace(cs)
        t.textLine(s); c.drawText(t)
    c.setFont(FONT, size)
    if bold:
        c.setStrokeColor(color); c.setLineWidth(size * 0.028)
        c.saveState(); _draw(2); c.restoreState()
    else:
        _draw(0)
    return w

def vtext(x, y_top, lines, size, color, lh=1.34, align="left", box_w=None, bold=False):
    for i, ln in enumerate(lines):
        text(x, y_top + i * (size * lh / IN), ln, size, color, align=align, box_w=box_w, bold=bold)

def header(eyebrow_jp, eyebrow_en, headline, sub=None):
    text(0.55, 0.5, eyebrow_jp, 11, PRIMARY, bold=True)
    w = stringWidth(eyebrow_jp, FONT, 11)
    text(0.55 + w / IN + 0.18, 0.55, eyebrow_en, 9, MUTED, cs=1.2)
    text(0.55, 0.82, headline, 23, DARK, bold=True)
    if sub:
        text(0.56, 1.5, sub, 12, MUTED)
    hline(0.55, 12.78, 1.95, RULE, 0.8)

def takeaway(txt):
    rrect(0.55, 6.1, 12.23, 0.52, fill=LIGHT)
    text(0.75, 6.22, "ポイント", 11.5, ACCENT, bold=True)
    text(1.75, 6.23, txt, 11.5, DARK)

def footer(src, page):
    hline(0.55, 12.78, 6.85, RULE, 0.8)
    text(0.55, 6.93, src, 8.5, MUTED)
    text(11.9, 6.93, f"現状レポート ｜ {page} / {TOTAL}", 9, MUTED, align="right", box_w=0.88)

def callout(x, y, w, h, lines, size=10.5):
    rrect(x, y, w, h, fill=WHITE, stroke=PRIMARY, lw=1.0, r=0.05)
    vtext(x + 0.16, y + 0.13, lines, size, DARK, lh=1.35)

def leader(x1, y1, x2, y2):
    c.setStrokeColor(PRIMARY); c.setLineWidth(0.9)
    c.line(X(x1), Yt(y1), X(x2), Yt(y2))

# =================== COVER ===================
c.setFillColor(WHITE); c.rect(0, 0, PW, PH, fill=1, stroke=0)
text(0.55, 2.1, "現状レポート", 12, PRIMARY, bold=True)
text(0.55 + stringWidth("現状レポート", FONT, 12) / IN + 0.2, 2.16, "DATA PROTECTION LANDSCAPE", 9.5, MUTED, cs=1.4)
vtext(0.55, 2.7, ["データ保護をめぐる現状", "― 警察庁統計・国内事例・制度動向 ―"], 26, DARK, lh=1.5, bold=True)
hline(0.55, 12.78, 4.35, RULE, 0.8)
toc = [("1", "警察庁統計", "バックアップを取っていても、約8割は復旧できていない"),
       ("2", "国内事例",   "アサヒGHD、ランサム被害で営業利益 約370億円弱の減益"),
       ("3", "制度動向",   "IPA「情報セキュリティ5か条」にバックアップが追加され6か条に"),
       ("4", "公式推奨",   "IPAが推奨する「ランサムウェアに強いバックアップ」の4条件")]
for wk in sorted(WEEKS, key=lambda w: w["no"])[-4:]:  # 直近4週まで表示
    toc.append((str(4 + wk["no"]), "週次PICK", f"週次ピックアップ（{wk['period']}）"))
ty = 4.55
step = min(0.44, 2.2 / len(toc))
for num, cat, headline_ in toc:
    rect(0.55, ty, 0.34, 0.34, fill=LIGHT, stroke=BORDER, lw=0.7)
    text(0.55, ty + 0.055, num, 12, ACCENT, align="center", box_w=0.34)
    text(1.1, ty + 0.06, cat, 12.5, PRIMARY, bold=True)
    text(2.75, ty + 0.07, headline_, 12, DARK)
    ty += step
text(0.55, 6.93, "2026年8月〜 ｜ 公開情報より作成 ｜ 週次ピックアップを随時追記", 9, MUTED)
c.showPage()

# =================== PAGE 1 : 警察庁統計 ===================
c.setFillColor(WHITE); c.rect(0, 0, PW, PH, fill=1, stroke=0)
header("警察庁統計", "NATIONAL POLICE AGENCY DATA",
       "バックアップを取っていても、約8割は復旧できていない",
       "警察庁が半期ごとに公表する公式統計。ランサムウェア被害の実態を、警察が把握した実被害ベースで集計している。")
lx, lw_ = 0.55, 5.6
text(lx, 2.2, "警察庁統計が示す実態", 12.5, ACCENT, bold=True)
rows = [("約9割", "被害企業はバックアップを取得していた"),
        ("約2割", "感染前の水準まで復旧できた企業"),
        ("67%",  "復旧できなかった企業で「バックアップも暗号化」"),
        ("6割超", "侵入経路はVPN機器等の脆弱性")]
ry = 2.65
for big, desc in rows:
    text(lx + 0.05, ry + 0.2, big, 15, PRIMARY, bold=True)
    text(lx + 1.75, ry + 0.22, desc, 12, DARK)
    hline(lx, lx + lw_, ry + 0.72, RULE, 0.6)
    ry += 0.82
rx, rw = 6.7, 6.08
text(rx, 2.2, "バックアップからの復旧可否（被害組織）", 12.5, ACCENT, bold=True)
text(rx, 2.72, "被害組織の約8割は、バックアップから復旧できていない", 14, DARK, bold=True)
barY, barH = 3.3, 0.6
redW = rw * 0.8
rect(rx, barY, redW, barH, fill=PRIMARY)
rect(rx + redW, barY, rw - redW, barH, fill=LIGHT, stroke=BORDER, lw=0.8)
text(rx + 0.12, barY + 0.19, "復旧できず 約8割", 12, WHITE, bold=True)
text(rx + redW, barY + 0.21, "復旧 約2割", 10.5, ACCENT, align="center", box_w=rw - redW, bold=True)
callout(rx + 0.9, 4.35, 5.1, 0.95,
        ["民間ベンダーの観測ではなく、警察が捜査・報告を通じて",
         "把握した実被害の集計。国の公式統計である点が重要。"], 10.5)
leader(rx + 1.7, 4.35, rx + 1.2, barY + barH)
takeaway("バックアップの「有無」ではなく、攻撃後も無事に残っているかが復旧を分けている。")
footer("出典：警察庁「サイバー空間をめぐる脅威の情勢等について」（半期公表・令和6〜7年）より作成。", 1)
c.showPage()

# =================== PAGE 2 : アサヒ事件 ===================
c.setFillColor(WHITE); c.rect(0, 0, PW, PH, fill=1, stroke=0)
header("国内事例", "CASE: ASAHI GROUP HOLDINGS",
       "アサヒGHD、ランサム被害で営業利益 約370億円弱の減益",
       "2025年9月のサイバー攻撃で受注・出荷システムが停止。主力商品の供給が滞り、店頭で品薄が発生した。")
text(0.55, 2.15, "事件の経過", 12.5, ACCENT, bold=True)
tlY = 2.95
hline(0.9, 12.4, tlY, PRIMARY, 1.4)
miles = [(1.35, "9/29", ["サイバー攻撃で", "システム障害が発生"]),
         (4.05, "9/29", ["ネットワーク遮断", "データセンター隔離"]),
         (6.75, "10/3", ["ランサムウェアによる", "攻撃と公表"]),
         (9.45, "10/7", ["犯行集団Qilinが声明", "同社は身代金に応じず"]),
         (12.0, "その後", ["受注・出荷を順次再開", "完全復旧は翌年4月"])]
for mx, d, lines in miles:
    circle(mx, tlY, 0.07, fill=PRIMARY)
    text(mx, tlY - 0.42, d, 11.5, PRIMARY, align="center", bold=True)
    vtext(mx - 1.15, tlY + 0.18, lines, 10.5, DARK, align="center", box_w=2.3)
text(0.55, 4.15, "業績への影響（開示・報道ベース）", 12.5, ACCENT, bold=True)
text(0.6, 4.6, "営業利益ベースで約370億円弱の減益", 14, DARK, bold=True)
bx, bmaxw = 7.0, 3.4
byy = 4.45
for lbl, val in [("商品供給の一時停止", 200), ("システム復旧関連費用", 170)]:
    text(bx, byy + 0.05, lbl, 11.5, DARK)
    bw = bmaxw * val / 200.0
    rect(bx + 2.15, byy, bw * 0.55, 0.34, fill=PRIMARY)
    text(bx + 2.15 + bw * 0.55 + 0.1, byy + 0.05, f"約{val}億円", 11.5, ACCENT, bold=True)
    byy += 0.52
text(7.0, byy + 0.05, "※ 金額は概算。上記2項目で影響の大半を占める。", 9.5, MUTED)
callout(0.6, 5.3, 5.9, 0.62,
        ["侵入は障害発生の約10日前とされ、拠点のネットワーク機器を経由して",
         "管理者権限が奪取された（記者会見・報道より）。"], 9.5)
takeaway("損失の大半は身代金ではなく、事業停止とシステム復旧のコストだった。")
footer("出典：アサヒグループホールディングスの公表資料・決算関連開示および各種報道（2025〜2026年）より作成。", 2)
c.showPage()

# =================== PAGE 3 : IPA 6か条 ===================
c.setFillColor(WHITE); c.rect(0, 0, PW, PH, fill=1, stroke=0)
header("制度動向", "IPA / METI POLICY SHIFT",
       "IPA「情報セキュリティ5か条」にバックアップが追加され6か条に",
       "中小企業向けの最も基本的な対策集（SECURITY ACTION一つ星の宣言対象）。2026年度・ガイドライン第4.0版で6項目めが加わった。")
lx = 0.55
text(lx, 2.15, "情報セキュリティ6か条（第4.0版）", 12.5, ACCENT, bold=True)
items = ["OS・ソフトウェアを最新に保つ", "ウイルス対策ソフトを導入する", "パスワードを強化する",
         "共有設定を見直す", "脅威や攻撃の手口を知る"]
iy = 2.6
for i, it in enumerate(items, 1):
    rect(lx, iy, 0.34, 0.34, fill=LIGHT, stroke=BORDER, lw=0.7)
    text(lx, iy + 0.055, str(i), 12, ACCENT, align="center", box_w=0.34)
    text(lx + 0.5, iy + 0.06, it, 12.5, DARK)
    iy += 0.5
rect(lx, iy, 0.34, 0.34, fill=PRIMARY)
text(lx, iy + 0.055, "6", 12, WHITE, align="center", box_w=0.34, bold=True)
text(lx + 0.5, iy + 0.06, "バックアップを取ろう！", 12.5, PRIMARY, bold=True)
text(lx + 3.2, iy + 0.08, "← 2026年度改訂で追加", 10.5, PRIMARY)
text(lx, iy + 0.62, "※ 6項目めの具体策は次ページ（IPA公式推奨）を参照。", 10, MUTED)
rx = 7.05
text(rx, 2.15, "改訂の意味合い", 12.5, ACCENT, bold=True)
imps = [("国の基本指針に明記", ["最上位の脅威（ランサムウェア）への備えとして、", "「復旧手段の確保」が基本対策に格上げされた"]),
        ("取引条件へ波及", ["発注元が取引先にSECURITY ACTION宣言や", "SCS評価制度への対応を求める動きが拡大"]),
        ("未対応は事業リスク", ["補助金申請・取引選定・サイバー保険の引受で", "不利になりうる"])]
byy = 2.6
for head, lines in imps:
    rrect(rx, byy, 5.72, 1.0, fill=WHITE, stroke=BORDER, lw=0.9, r=0.05)
    text(rx + 0.2, byy + 0.12, head, 13, ACCENT, bold=True)
    vtext(rx + 0.2, byy + 0.47, lines, 10.5, DARK, lh=1.3)
    byy += 1.12
takeaway("基本対策の位置づけが「推奨」から「取引の前提」へ移りつつある。")
footer("出典：IPA「中小企業の情報セキュリティ対策ガイドライン 第4.0版」（2026年3月）／SECURITY ACTION／経済産業省SCS評価制度より作成。", 3)
c.showPage()

# =================== PAGE 4 : IPA推奨 ===================
c.setFillColor(WHITE); c.rect(0, 0, PW, PH, fill=1, stroke=0)
header("公式推奨", "IPA RECOMMENDATIONS",
       "IPAが推奨する「ランサムウェアに強いバックアップ」の4条件",
       "6項目めの「バックアップを取ろう！」の具体策として、IPAはランサムウェア対策特設ページ等で次の4点を示している。")
cards = [("1", "オフラインで保管する",
          ["取得したらネットワークから切り離す（外付けHDD等は", "都度取り外す）。接続されたままのバックアップは", "本体と一緒に暗号化されうる。"]),
         ("2", "読み書きできない状態にする",
          ["バックアップ先を書き換え・削除できないように設定し、", "上書きや消去そのものを防ぐ。"]),
         ("3", "復元できるか定期的に確認する",
          ["バックアップから実際にリストア（復元）できるかを", "定期的にテストしておく。"]),
         ("4", "複数世代・遠隔地に分ける",
          ["世代を複数残し、離れた場所にも保管する", "（3-2-1バックアップの考え方）。"])]
cw, chh, gap = 5.94, 1.55, 0.35
positions = [(0.55, 2.25), (0.55 + cw + gap, 2.25), (0.55, 2.25 + chh + 0.28), (0.55 + cw + gap, 2.25 + chh + 0.28)]
for (num, head, lines), (px, py) in zip(cards, positions):
    rrect(px, py, cw, chh, fill=WHITE, stroke=BORDER, lw=0.9, r=0.05)
    rect(px + 0.2, py + 0.2, 0.36, 0.36, fill=PRIMARY)
    text(px + 0.2, py + 0.26, num, 13, WHITE, align="center", box_w=0.36, bold=True)
    text(px + 0.72, py + 0.25, head, 14, DARK, bold=True)
    vtext(px + 0.24, py + 0.72, lines, 10.5, DARK, lh=1.32)
text(0.57, 5.78, "※ IPA原文の表現は「オフラインで保管」「読み書きできないようにする」。『イミュータブル／WORM／Object Lock』は同趣旨を指すベンダー用語。", 9.5, MUTED)
takeaway("共通するのは、バックアップ自体を攻撃から隔離し、確実に戻せる状態を保つこと。")
footer("出典：IPA「ランサムウェア対策特設ページ」「ランサムウェアの脅威と対策」より作成（表現は要約）。", 4)
c.showPage()

# =================== WEEKLY PICKUP PAGES ===================
for wk in sorted(WEEKS, key=lambda w: w["no"]):
    c.setFillColor(WHITE); c.rect(0, 0, PW, PH, fill=1, stroke=0)
    header("週次ピックアップ", "WEEKLY HIGHLIGHTS",
           f"今週プレゼンで使うべきニュース（{wk['period']}）",
           wk["summary"])
    iy = 2.2
    n = len(wk["picks"])
    rowh = min(0.76, 3.75 / max(n, 1))
    for i, (title, role, nums) in enumerate(wk["picks"], 1):
        rect(0.55, iy, 0.3, 0.3, fill=PRIMARY)
        text(0.55, iy + 0.045, str(i), 11.5, WHITE, align="center", box_w=0.3, bold=True)
        text(1.0, iy + 0.03, title, 12.5, DARK, bold=True)
        text(1.0, iy + 0.35, f"使いどころ: {role} ｜ {nums}", 9.8, MUTED)
        hline(0.55, 12.78, iy + rowh - 0.08, RULE, 0.5)
        iy += rowh
    if wk.get("note"):
        text(0.57, iy + 0.02, "※ " + wk["note"], 9.5, MUTED)
    takeaway("この週のピックはDB「Wasabi 販促ニュース（データ保護）」および週次ピックアップ（Notion）と対応。")
    footer("出典：各ピックの出典はDB登録ページを参照。", 4 + wk["no"])
    c.showPage()

c.save()
print("saved:", OUT, "pages:", 1 + TOTAL)
