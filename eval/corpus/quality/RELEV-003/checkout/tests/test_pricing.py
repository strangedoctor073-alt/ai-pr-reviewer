from shop.pricing import apply_discount


def test_discount():
    assert apply_discount(100, 0.5) == 50
