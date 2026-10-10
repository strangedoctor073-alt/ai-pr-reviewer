from app.billing import charge


def test_charge():
    assert charge("c1", 100)["amount"] == 10000
