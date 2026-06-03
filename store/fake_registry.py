import hashlib
import random
from typing import Any, Dict

# Small built-in persona and product lists used by the fake registry.
USERS = [
    {"username": "ada.ellis", "name": "Ada Ellis", "email": "ada.ellis@honeyhaven.local", "role": "finance"},
    {"username": "noah.patel", "name": "Noah Patel", "email": "noah.patel@honeyhaven.local", "role": "support"},
    {"username": "li.chen", "name": "Li Chen", "email": "li.chen@honeyhaven.local", "role": "ops"},
    {"username": "maria.kim", "name": "Maria Kim", "email": "maria.kim@honeyhaven.local", "role": "sales"},
]

PRODUCTS = ["wildflower", "forest amber", "acacia", "reserve"]


def _int_seed(*parts: Any) -> int:
    raw = "::".join(str(p) for p in parts if p is not None)
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return int(digest[:16], 16)


def persona_for_session(session_id: str) -> Dict[str, str]:
    seed = _int_seed(session_id)
    rng = random.Random(seed)
    return rng.choice(USERS)


def order_for_persona(persona: Dict[str, str], order_ref: str | None = None) -> Dict[str, Any]:
    key = (persona.get("username") or "anon") + (order_ref or "")
    seed = _int_seed(key)
    rng = random.Random(seed)
    order_id = f"ORD-{rng.randint(10000, 99999)}"
    product = rng.choice(PRODUCTS)
    amount = round(rng.uniform(9.5, 248.0), 2)
    return {"order_id": order_id, "product": product, "amount": amount, "status": rng.choice(["open", "paid", "refunded"])}


def payment_for_order(order_id: str) -> Dict[str, Any]:
    seed = _int_seed(order_id)
    rng = random.Random(seed)
    payment_id = f"pi_{rng.randint(100000, 999999)}"
    return {"payment_id": payment_id, "merchant_reference": order_id, "card_last4": rng.choice(["4242", "1111", "1881"]), "amount": round(rng.uniform(18, 248), 2), "currency": "USD", "status": rng.choice(["pending", "captured", "failed", "refunded"])}


def ticket_for_subject(subject: str, email: str | None = None) -> Dict[str, Any]:
    seed = _int_seed(subject, email or "")
    rng = random.Random(seed)
    ticket_id = f"TCK-{rng.randint(3000, 9999)}"
    requester = (email or rng.choice(USERS)["email"])[:255]
    return {"ticket_id": ticket_id, "requester_email": requester, "subject": subject, "status": rng.choice(["open", "pending", "waiting_on_customer"]), "priority": rng.choice(["low", "normal", "high"])}
