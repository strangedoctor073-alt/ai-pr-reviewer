from shop.pricing import apply_discount


def total(items, rate):
    return apply_discount(sum(items), rate)
