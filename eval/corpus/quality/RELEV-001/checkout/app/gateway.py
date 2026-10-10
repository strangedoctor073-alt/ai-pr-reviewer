from app.billing import charge


def handle(request):
    return charge(request["customer"], request["amount"])
