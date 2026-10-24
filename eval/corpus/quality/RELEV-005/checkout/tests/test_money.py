from core.money import cents


def test_cents():
    assert cents(1.0) == 100
