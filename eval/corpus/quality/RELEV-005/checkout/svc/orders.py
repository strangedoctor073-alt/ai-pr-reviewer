from core.money import cents


def price(order):
    return cents(order['amount'])
