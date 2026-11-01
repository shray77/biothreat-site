#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_events.py — разовая коррекция данных BioThreat Watch по аудиту SW-29
(repos/vet-swarm-audit/swarm-2026-11-01/29-biothreat-data-science/audit-report.md)
и QA-09 (…/09-biothreat-hardqa/qa-report.md). Срез данных: 2026-10-31T16:40Z (58 items).

ЧТО ИСПРАВЛЯЕТ (все значения — из отчёта SW-29 / его приложений, не из головы):
  1. disease: 14 событий — поле болезни расходится с болезнью из заголовка
     первоисточника (SW-29 §2 п.5: ящур→АЧС — Addo ×2, Алжир, Намибия, Корея
     + FMD-новость с «классической чумой свиней»; HFMD→«грипп птиц» (Вьетнам);
     bluetongue→«ньюкасл»; 6× disease=null с названной в заголовке болезнью).
  2. country: синонимы одной страны (SW-29 §7): «Южно-Африканская Республика»→«ЮАР»,
     «Северная Англия»→«Великобритания», «Англия»→«Великобритания» (QA-09 Ш1:
     счётчик «стран в радаре» 13 → реальных 11).
  3. published_at: 4 события, проверенных по первоисточникам (SW-29 §2 п.7) —
     фид терял таймзону, время было на 6–7 ч раньше факта (минуты совпадали).
  4. distance_km: 11 событий — словарь «грубых корзин» расходился с независимым
     гаверсинусом SW-29 (02_distance_check.log) на 309–2122 км (заявлен допуск
     ±100–200 км). Уровень пересчитан по наблюдаемым корзинам данных
     (0=граница; ≤1800=наблюдение; >2500=фон) — только там, где новая дистанция
     однозначно меняет корзину.
  5. ai_summary: 7 событий — механическая замена словосочетания болезни, чтобы
     резюме не противоречило исправленному полю disease (ящур ≠ АЧС).

events.xml (RSS-дубликат витрины) синхронизируется по тем же правилам, что
использует воркер: title = «[level] disease[ — country]: title»,
description = «summary · verdict: … · title», pubDate = RFC822 GMT.

Запуск: python3 scripts/fix_events.py (из корня репо). Идемпотентен: повторный
запуск ничего не меняет (все правки — сопоставлением fingerprint + проверка
старого значения). Воркер biothreat перезапишет events.json в следующем цикле —
скрипт оставлен как спецификация нормализации для конвейера (rss-core/biothreat).
"""
import json, re, sys, io
from datetime import datetime, timezone
from email.utils import format_datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

JSON_PATH, XML_PATH = "events.json", "events.xml"

# ---------- таблицы правок (ключ — fingerprint события) ----------

# 1. поле болезни: fingerprint -> (старое значение, новое)
DISEASE = {
    # ящур, выданный за АЧС/КЧС (SW-29 §2 п.5, §5: Addo ×2, Алжир, Намибия, Корея;
    # «Foot-and-Mouth Disease Delays Reopening» — FMD-новость с полем «КЧС»)
    "5ab3fbe7f33ce85556eac4cbd835736c6d662ea0": ("африканская чума свиней", "ящур"),   # Намибия, ЦБ/FMD
    "49cdec61012b621aaa1e9fc97326c3ed165e36ed": ("африканская чума свиней", "ящур"),   # Алжир
    "4e0b598bc4684fed74de33adef3d4c9880a317cb": ("классическая чума свиней", "ящур"), # FMD delays reopening
    "9d37d80c9d4be7b13d6ebf2b0cb2d0bbfd936047": ("африканская чума свиней", "ящур"),  # Южная Корея, FMD
    "1c631a360cad1e493cdf5bebbdc3c3ee3e278279": ("африканская чума свиней", "ящур"),  # ЮАР, Addo (Daily Maverick)
    "12060e3ee8d459ff6cc6692725c759280a81d298": ("африканская чума свиней", "ящур"),  # ЮАР-Респ., Addo kudu
    # HFMD (hand-foot-mouth, Вьетнам), выданный за «грипп птиц» (SW-29 §2 п.5)
    "ba9083aadcc1dbc0fbbbcbcad37a5d258752161d": ("грипп птиц", "болезнь «рука-нога-рот» (HFMD)"),
    # bluetongue-новость с полем «ньюкасл» (метод SW-29: болезнь из заголовка)
    "5de5858263e9da3e96179296445523c02ca208e2": ("болезнь ньюкасла", "катаральная лихорадка овец (блютонг)"),
    # disease=null, болезнь названа в заголовке (SW-29 §2 п.5: «у 7 из 11 видна в заголовке»;
    # 7-й, «vet's FMD fears amid bluetongue outbreak», не заполняем — в заголовке ДВЕ болезни)
    "3aa52bb0d42ffb7a563bc2db93270f7883861a81": (None, "африканская чума свиней"),    # ASF biosecurity
    "a0cd46a8b4577dcb9e54fa018977967a8ce86245": (None, "ящур"),                        # Намибия FMD, юр. последствия
    "7124d866a2e8436cc99d7c0a79abe7eddaed4396": (None, "грипп птиц"),                  # Utah mink farm
    "63c8dfd6921ad5b7edd1ea58a72a31482d0ee03a": (None, "грипп птиц"),                  # Illinois HPAI
    "51cfee600f058b9ae32259da4eaf25a3383e31e1": (None, "африканская чума свиней"),    # Cebu ASF
    "1124c68e2b42d93bffd9602d69a1653b8dce9302": (None, "африканская чума свиней"),    # ASF prediction project
}

# 2. нормализация написаний стран (SW-29 §7, QA-09 Ш1)
COUNTRY = {
    "12060e3ee8d459ff6cc6692725c759280a81d298": ("Южно-Африканская Республика", "ЮАР"),
    "c40f107782959cd3c8299635aade5223b49917c3": ("Северная Англия", "Великобритания"),
    "41424cbfa7c246c0273807ce5f732ea44ea7488b": ("Англия", "Великобритания"),
}

# 3. published_at: время первоисточника по SW-29 §2 п.7 (фид терял таймзону, −6…−7 ч)
PUBLISHED = {
    "9080d0bdf4fd887ae9efeb8de92e6cac9ff375b3": ("2026-10-30T16:52:00.000Z", "2026-10-30T23:53:00.000Z"),  # yahoo/Колорадо
    "acc05697e871c6ac6c0344ab9470d520d63e7497": ("2026-10-29T08:44:00.000Z", "2026-10-29T15:44:00.000Z"),  # poultrynews/Нидерланды
    "1c631a360cad1e493cdf5bebbdc3c3ee3e278279": ("2026-10-22T10:06:00.000Z", "2026-10-22T17:06:00.000Z"),  # dailymaverick/Addo
    "c40f107782959cd3c8299635aade5223b49917c3": ("2026-10-20T11:12:00.000Z", "2026-10-20T17:12:00.000Z"),  # chroniclelive/Нортумберленд
}

# 4. distance_km — независимый гаверсинус SW-29 (02_distance_check.log), |Δ|>200 км
DISTANCE = {
    "5ab3fbe7f33ce85556eac4cbd835736c6d662ea0": (6500, 7682),   # Намибия
    "b4580fcf16e5af16d1dc2223dc9e53021514960c": (1600, 3722),   # Вьетнам
    "1bdd33a0c3ac942a1530b0f9b6dd3a88e59de62d": (9600, 8561),   # Гренада
    "1bb528c3c23c0a1e44f6abbef7a745dbac33ab48": (1800, 1491),   # Италия
    "c2ce64013d1192671a5ada767e30a74ba2e2b5dd": (8000, 10082),  # Бразилия
    "bbcacae33c55eacc954b097c73f98e5616aaee11": (1200, 852),    # Дания
    "b16db6125e8d448f3aa7e5873e5e6549a551f674": (2500, 1636),   # Великобритания
    "41424cbfa7c246c0273807ce5f732ea44ea7488b": (2500, 1636),   # Англия -> Великобритания
    "acc05697e871c6ac6c0344ab9470d520d63e7497": (1600, 1186),   # Нидерланды
    "1c631a360cad1e493cdf5bebbdc3c3ee3e278279": (7000, 8190),   # ЮАР
    "c40f107782959cd3c8299635aade5223b49917c3": (2500, 1636),   # Северная Англия -> Великобритания
}

# 4b. level — пересчёт ТОЛЬКО при однозначной смене корзины (наблюдаемая шкала данных:
#     0=«граница», 1200/1600/1800=«наблюдение», 2500+=«фон»; SW-29: «пороги грубые»)
LEVEL = {
    "b4580fcf16e5af16d1dc2223dc9e53021514960c": ("наблюдение", "фон"),       # Вьетнам 1600→3722
    "b16db6125e8d448f3aa7e5873e5e6549a551f674": ("фон", "наблюдение"),      # Вел. 2500→1636
    "41424cbfa7c246c0273807ce5f732ea44ea7488b": ("фон", "наблюдение"),       # Англия 2500→1636
    "c40f107782959cd3c8299635aade5223b49917c3": ("фон", "наблюдение"),       # Сев. Англия 2500→1636
}

# 5. ai_summary — механическая замена болезни в резюме (иначе карточка противоречит
#    исправленному полю «возбудитель»); согласование падежа — тривиальное
SUMMARY = {
    "5ab3fbe7f33ce85556eac4cbd835736c6d662ea0": ("вспышкой африканской чумы свиней", "вспышкой ящура"),
    "49cdec61012b621aaa1e9fc97326c3ed165e36ed": ("вспышки африканской чумы свиней", "вспышки ящура"),
    "4e0b598bc4684fed74de33adef3d4c9880a317cb": ("Случаи классической чумы свиней вновь", "Случаи ящура вновь"),
    "9d37d80c9d4be7b13d6ebf2b0cb2d0bbfd936047": ("случай африканской чумы свиней на", "случай ящура на"),
    "a0cd46a8b4577dcb9e54fa018977967a8ce86245": ("вспышки африканской чумы свиней в Намибии", "вспышки ящура в Намибии"),
    "1c631a360cad1e493cdf5bebbdc3c3ee3e278279": ("Кризис африканской чумы свиней в парке", "Кризис ящура в парке"),
    "12060e3ee8d459ff6cc6692725c759280a81d298": ("Подтверждено африканская чума свиней у куду", "Подтвержден ящур у куду"),
}

def xml_escape(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def xml_title(it):
    # формат воркера: «[level] disease — country: title»; без болезни — «[level] country: title»;
    # без обоих — «[level] title» (двоеточие не ставится)
    head = "[%s]" % it["level"]
    if it.get("disease"):
        head += " " + it["disease"]
    if it.get("country"):
        head += (" — " if it.get("disease") else " ") + it["country"]
    sep = ": " if (it.get("disease") or it.get("country")) else " "
    return xml_escape(head + sep + it["title"])

def xml_description(it):
    parts = []
    if it.get("ai_summary"):
        parts.append(it["ai_summary"])
    parts.append("verdict: %s" % it["verdict"])
    parts.append(it["title"])
    return xml_escape(" · ".join(parts))

def xml_pubdate(it):
    dt = datetime.fromisoformat(it["published_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
    return format_datetime(dt, usegmt=True)

def main():
    j = json.load(open(JSON_PATH, encoding="utf-8"))
    orig = {i["fingerprint"]: dict(i) for i in j["items"]}
    by_fp = {i["fingerprint"]: i for i in j["items"]}
    touched = set()

    def apply(table, field, label):
        n = 0
        for fp, (old, new) in table.items():
            if fp not in by_fp:
                sys.exit("ОШИБКА: fingerprint нет в данных: %s (%s)" % (fp, label))
            it = by_fp[fp]
            if it.get(field) == new:
                continue  # уже исправлено (идемпотентность)
            if it.get(field) != old:
                sys.exit("ОШИБКА: %s у %s = %r, ожидалось %r" % (field, fp[:8], it.get(field), old))
            it[field] = new
            touched.add(fp); n += 1
        print("  %-10s исправлено: %d" % (label, n))

    def apply_sub(table, label):
        """substring-замена внутри ai_summary (согласование падежа — тривиальное)"""
        n = 0
        for fp, (old, new) in table.items():
            if fp not in by_fp:
                sys.exit("ОШИБКА: fingerprint нет в данных: %s (%s)" % (fp, label))
            it = by_fp[fp]
            s = it.get("ai_summary") or ""
            if new in s:
                continue  # уже исправлено (идемпотентность)
            if old not in s:
                sys.exit("ОШИБКА: %s не содержит %r" % (fp[:8], old))
            it["ai_summary"] = s.replace(old, new, 1)
            touched.add(fp); n += 1
        print("  %-10s исправлено: %d" % (label, n))

    print("== events.json (%d items) ==" % len(j["items"]))
    apply(DISEASE, "disease", "disease")
    apply(COUNTRY, "country", "country")
    apply(PUBLISHED, "published_at", "published_at")
    apply(DISTANCE, "distance_km", "distance_km")
    apply(LEVEL, "level", "level")
    apply_sub(SUMMARY, "ai_summary")

    raw = open(JSON_PATH, encoding="utf-8").read()
    new_raw = json.dumps(j, ensure_ascii=False, indent=2) + "\n"
    if new_raw != raw:
        open(JSON_PATH, "w", encoding="utf-8", newline="\n").write(new_raw)
        print("  events.json записан (%d событий затронуто)" % len(touched))

    # ---------- events.xml: точечная перезапись <title>/<pubDate>/<description> ----------
    xraw = open(XML_PATH, encoding="utf-8").read()
    n_xml = 0
    for fp in touched:
        o, it = orig[fp], by_fp[fp]
        changed = any(o.get(f) != it.get(f) for f in
                      ("level", "disease", "country", "published_at", "ai_summary", "title"))
        if not changed:
            continue
        # блок <item>…</item>, содержащий guid == fingerprint
        m = re.search(r"[ \t]*<item>\n(?:(?!</item>).)*?<guid isPermaLink=\"false\">%s</guid>(?:(?!</item>).)*?</item>" % fp, xraw, re.S)
        if not m:
            sys.exit("ОШИБКА: item не найден в XML: %s" % fp[:8])
        block = m.group(0)
        new_block = block
        for tag, val in (("title", xml_title(it)), ("pubDate", xml_pubdate(it)), ("description", xml_description(it))):
            new_block = re.sub(r"([ \t])<%s>.*?</%s>" % (tag, tag), r"\1<%s>%s</%s>" % (tag, val, tag), new_block, count=1)
        if new_block != block:
            xraw = xraw.replace(block, new_block, 1)
            n_xml += 1
    open(XML_PATH, "w", encoding="utf-8", newline="\n").write(xraw)
    print("== events.xml: обновлено item-блоков: %d ==" % n_xml)

if __name__ == "__main__":
    main()
