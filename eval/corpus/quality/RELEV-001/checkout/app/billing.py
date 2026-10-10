def charge(customer_id, amount):
    rate = amount * 100
    return {"customer": customer_id, "amount": rate}
