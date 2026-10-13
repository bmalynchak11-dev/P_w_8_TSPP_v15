import pytest
from conftest import load

M = load(5)

@pytest.mark.parametrize("args, expected", [
    # 1. Секрет із токеном Bearer блокує запит
    (
        ("Використовуй Bearer secret_token_1234567890 для авторизації", []),
        {
            "blocked": True,
            "reasons": ["токен доступу"],
            "text": None,
            "mapping": {},
            "counts": {}
        }
    ),
    # 2. Звичайні числа та неповні номери телефонів не змінюються
    (
        ("У заявці вказано інвентарний номер 123456789 і код 044123.", []),
        {
            "blocked": False,
            "reasons": [],
            "text": "У заявці вказано інвентарний номер 123456789 і код 044123.",
            "mapping": {},
            "counts": {}
        }
    ),
    # 3. Комплексний випадок: кілька однакових телефонів і пошт
    (
        (
            "Зателефонуйте на +38 (050) 123-45-67 або 0501234567, email: test@exam.ua",
            [["Іван Петренко", "Івану Петренку"]]
        ),
        {
            "blocked": False,
            "reasons": [],
            "text": "Зателефонуйте на [ТЕЛЕФОН_1] або [ТЕЛЕФОН_1], email: [EMAIL_1]",
            "mapping": {
                "[ТЕЛЕФОН_1]": "+38 (050) 123-45-67",
                "[EMAIL_1]": "test@exam.ua"
            },
            "counts": {
                "ТЕЛЕФОН": 1,
                "EMAIL": 1
            }
        }
    ),
])
def test_my_cases(args, expected):
    assert M.anonymize(*args) == expected