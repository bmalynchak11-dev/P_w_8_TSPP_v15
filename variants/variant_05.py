import re

def anonymize(text: str, roster: list) -> dict:
    # 1. Перевірка валідності вхідного тексту
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Порожній текст")

    # 2. Перевірка реєстру осіб: одна форма не може належати двом особам
    seen_forms = {}
    for person_idx, forms in enumerate(roster):
        for form in forms:
            if form in seen_forms and seen_forms[form] != person_idx:
                raise ValueError(f"Форма «{form}» належить двом особам")
            seen_forms[form] = person_idx

    # 3. Перевірка секретів (у визначеному правилами порядку)
    reasons = []

    # Ключ API (латинські API): sk- і щонайменше 16 латинських літер чи цифр
    if re.search(r"\bsk-[A-Za-z0-9]{16,}\b", text):
        reasons.append("ключ API")

    # Токен доступу: Bearer і щонайменше 16 символів з літер, цифр, -, _, .
    if re.search(r"\bBearer\s+[A-Za-z0-9_\-\.]{16,}\b", text):
        reasons.append("токен доступу")

    # Пароль: слово пароль, password або passwd, далі : чи = і значення
    if re.search(r"(?i)\b(пароль|password|passwd)\s*[:=]\s*\S+", text):
        reasons.append("пароль")

    if reasons:
        return {
            "blocked": True,
            "reasons": reasons,
            "text": None,
            "mapping": {},
            "counts": {}
        }

    # 4. Пошук сутностей для знеособлення
    matches = []

    # Електронні адреси: [\w.+-]+@[\w-]+(\.[\w-]+)+
    email_regex = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    for m in email_regex.finditer(text):
        matches.append({
            "start": m.start(),
            "end": m.end(),
            "type": "EMAIL",
            "val": m.group(),
            "key": m.group()
        })

    # Форми імен із реєстру (точний збіг, чутливий до регістру, не всередині слова)
    for person_idx, forms in enumerate(roster):
        for form in forms:
            if not form:
                continue
            escaped_form = re.escape(form)
            pattern = rf"(?<![^\W_]){escaped_form}(?![^\W_])"
            for m in re.finditer(pattern, text):
                matches.append({
                    "start": m.start(),
                    "end": m.end(),
                    "type": "ОСОБА",
                    "val": m.group(),
                    "key": person_idx
                })

    # Телефони: послідовність \+?[\d\s()-]{8,}\d, цифри: 380 + 9 цифр або 0 + 9 цифр
    phone_pattern = re.compile(r"\+?\d[\d\s()-]{8,}\d")
    for m in phone_pattern.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        phone_key = None
        if len(digits) == 12 and digits.startswith("380"):
            phone_key = digits
        elif len(digits) == 10 and digits.startswith("0"):
            phone_key = "38" + digits

        if phone_key:
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "type": "ТЕЛЕФОН",
                "val": m.group(),
                "key": phone_key
            })

    # 5. Розв'язання перетинів
    matches.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))

    non_overlapping = []
    last_end = 0
    for match in matches:
        if match["start"] >= last_end:
            non_overlapping.append(match)
            last_end = match["end"]

    # 6. Призначення однакових міток у порядку першої появи
    label_counters = {"ОСОБА": 0, "EMAIL": 0, "ТЕЛЕФОН": 0}
    assigned_labels = {}
    mapping = {}

    for match in non_overlapping:
        cat = match["type"]
        key = (cat, match["key"])
        if key not in assigned_labels:
            label_counters[cat] += 1
            assigned_labels[key] = f"[{cat}_{label_counters[cat]}]"
            mapping[assigned_labels[key]] = match["val"]
        match["label"] = assigned_labels[key]

    # 7. Збирання результуючого рядка
    result_chars = []
    cursor = 0
    for match in non_overlapping:
        result_chars.append(text[cursor:match["start"]])
        result_chars.append(match["label"])
        cursor = match["end"]
    result_chars.append(text[cursor:])

    counts = {cat: count for cat, count in label_counters.items() if count > 0}

    return {
        "blocked": False,
        "reasons": [],
        "text": "".join(result_chars),
        "mapping": mapping,
        "counts": counts
    }