#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_data.py — гейт согласованности данных BioThreat Watch после fix_events.py.

Проверяет (метод — как у аудита SW-29 check_data.py, блоки B/C/D/G):
  1. JSON валиден; XML валиден; число items совпадает.
  2. JSON ↔ XML по каждому guid: link, pubDate, title (формат воркера
     «[level] disease[ — country]: title»), description.
  3. Счётчики витрины: «стран в радаре» после нормализации синонимов (=11 на
     срезе 2026-10-31), события со страной без координат (CENTROIDS+REGION_FALLBACK
     из index.html) — ожидаемо 0 после добавления Кипра и алиасов.
  4. Поле disease vs болезнь в заголовке (keyword-гейт SW-29 §7) — ожидаемо 0
     расхождений для однозначных заголовков.

Запуск: python3 scripts/check_data.py (из корня репо). Код возврата != 0 при провале.
"""
import json, re, sys, io
from datetime import datetime
from email.utils import parsedate_to_datetime
import xml.etree.ElementTree as ET
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
FAIL = []

j = json.load(open("events.json", encoding="utf-8"))
items = j["items"]
tree = ET.parse("events.xml")
xitems = tree.getroot().findall(".//item")

# --- 1. структура ---
assert len(xitems) == len(items), "число items JSON(%d) != XML(%d)" % (len(items), len(xitems))
print("1. items: JSON=%d XML=%d — ок" % (len(items), len(xitems)))

# --- 2. JSON <-> XML ---
by_guid = {x.findtext("guid"): x for x in xitems}
jmap = {i["fingerprint"]: i for i in items}
assert set(by_guid) == set(jmap), "guid-множества различаются"

def title_expect(it):
    # формат воркера (см. scripts/fix_events.py): без болезни страна идёт без тире,
    # без болезни и страны — без двоеточия
    head = "[%s]" % it["level"]
    if it.get("disease"):
        head += " " + it["disease"]
    if it.get("country"):
        head += (" — " if it.get("disease") else " ") + it["country"]
    sep = ": " if (it.get("disease") or it.get("country")) else " "
    return head + sep + it["title"]

def desc_expect(it):
    parts = []
    if it.get("ai_summary"):
        parts.append(it["ai_summary"])
    parts.append("verdict: %s" % it["verdict"])
    parts.append(it["title"])
    return " · ".join(parts)

bad = Counter()
for g, x in by_guid.items():
    it = jmap[g]
    if x.findtext("link") != it["url"]:
        bad["link"] += 1
    xp = parsedate_to_datetime(x.findtext("pubDate"))
    jp = datetime.fromisoformat(it["published_at"].replace("Z", "+00:00"))
    if abs((xp - jp).total_seconds()) > 1:
        bad["pubDate"] += 1
    if (x.findtext("title") or "") != title_expect(it):
        bad["title"] += 1
    if (x.findtext("description") or "") != desc_expect(it):
        bad["description"] += 1
if bad:
    FAIL.append("JSON↔XML расхождения: %s" % dict(bad))
print("2. JSON↔XML (link/pubDate/title/description): расхождений %s" % (dict(bad) or "нет — ок"))

# --- 3. счётчики витрины (renderMeta) + алиасы из index.html ---
html = open("index.html", encoding="utf-8").read()
def obj_keys(name):
    m = re.search(name + r"\s*=\s*\{(.*?)\n\};", html, re.S)
    return set(re.findall(r'"([^"]+)"\s*:', m.group(1)))
def obj_pairs(name):
    m = re.search(name + r"\s*=\s*\{(.*?)\n\};", html, re.S)
    return dict(re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', m.group(1)))
CENT, RF = obj_keys("CENTROIDS"), obj_pairs("REGION_FALLBACK")

conf_ctrs_raw = sorted({i["country"] for i in items if i["verdict"] == "confirmed" and i.get("country")})
conf_ctrs = sorted({RF.get(c, c) for c in conf_ctrs_raw})
print("3. подтверждённые страны: сырые строки=%d (%s)" % (len(conf_ctrs_raw), ", ".join(conf_ctrs_raw)))
print("   с алиасами REGION_FALLBACK=%d (%s)" % (len(conf_ctrs), ", ".join(conf_ctrs)))
if len(conf_ctrs) != 11:
    FAIL.append("стран в радаре после нормализации = %d, ожидалось 11" % len(conf_ctrs))

no_geo = sorted({i["country"] for i in items if i.get("country") and i["country"] not in CENT and i["country"] not in RF})
print("   страны без координат (CENTROIDS/REGION_FALLBACK): %s" % (no_geo or "нет — ок"))
if no_geo:
    FAIL.append("страны без координат: %s" % no_geo)
n_geo = sum(1 for i in items if i.get("country") and (i["country"] in CENT or i["country"] in RF))
print("   событий с гео на карте: %d из %d (со страной: %d)" % (n_geo, len(items), sum(1 for i in items if i.get("country"))))

# --- 4. disease vs заголовок (keyword-гейт SW-29) ---
KW = [
    # HFMD проверяем раньше ящура и отсекаем «hand-foot-AND-mouth» от «foot-and-mouth»
    (r'hand[\s,()-]*foot[\s,()-]*(?:and[\s,()-]*)?mouth|\bhfmd\b', 'болезнь «рука-нога-рот» (HFMD)'),
    (r'(?<!hand-)foot[- ]and[- ]mouth|\bfmd\b', 'ящур'),
    (r'african swine fever|\basf\b', 'африканская чума свиней'),
    (r'avian (flu|influenza)|bird flu|\bh5n1\b|\bhpai\b', 'грипп птиц'),
    (r'lumpy skin|\blsd\b', 'нодулярный дерматит'),
    (r'newcastle', 'болезнь ньюкасла'),
    (r'classical swine fever|\bcsf\b|hog cholera', 'классическая чума свиней'),
    (r'bluetongue', 'катаральная лихорадка овец (блютонг)'),
]
mism = []
for it in items:
    tl = (it["title"] or "").lower()
    named = {name for pat, name in KW if re.search(pat, tl)}
    if len(named) != 1:
        continue  # болезнь не названа или названо несколько (напр. «FMD fears amid bluetongue») — не гейтим
    (name,) = named
    if it.get("disease") != name:
        mism.append((it["fingerprint"][:8], it.get("disease"), name, it["title"][:60]))
print("4. disease vs заголовок: расхождений %d" % len(mism))
for m in mism:
    print("   !!", m)
if mism:
    FAIL.append("остались расхождения disease/заголовок: %d" % len(mism))

# --- 5. инварианты словаря дистанций ---
dl = {}
for it in items:
    if it.get("distance_km") is not None:
        dl.setdefault(it["distance_km"], set()).add(it["level"])
amb = {d: s for d, s in dl.items() if len(s) > 1}
print("5. дистанция -> уровень, неоднозначных корзин: %s" % (amb or "нет — ок"))
if amb:
    FAIL.append("неоднозначные корзины дистанций: %s" % amb)

print("\n%s" % ("ПРОВЕРКИ ПРОЙДЕНЫ" if not FAIL else "ПРОВАЛЫ: " + "; ".join(FAIL)))
sys.exit(1 if FAIL else 0)
