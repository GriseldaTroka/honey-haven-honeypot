# Design Change Guide (Honeypot E-commerce)

Use this checklist whenever you change UI/design so the site stays realistic and research-safe.

## 1) Core principle

- Public-facing pages should look like a normal premium e-commerce website.
- Never expose security/honeypot language on storefront pages.
- Keep attacker observation passive: log and classify, do not block.

## 2) Files you can change safely for design

- `templates/base.html`
- `templates/home.html`
- `templates/shop.html`
- `templates/product_detail.html`
- `templates/login.html`
- `templates/register.html`
- `templates/checkout.html`
- `templates/fake_admin.html`
- `templates/research_analytics.html`
- `static/css/styles.css`
- `static/js/main.js`

## 3) Do not break these contracts

- Auth form field names:
  - `username`, `password`
- Checkout form field names:
  - `full_name`, `email`, `address`, `city`, `postal_code`, `card_name`, `card_number`, `expiry`, `cvv`
- Analytics chart bindings in `templates/research_analytics.html`:
  - Canvas IDs and JSON script IDs must stay in sync with JS.
- Required honeypot/research routes must remain reachable:
  - `/admin/` (decoy), `/login/`, `/api/login`, `/research/analytics/`, `/research/export/csv/`

## 4) UI quality checklist

- Consistent spacing, buttons, and typography across pages.
- Mobile-friendly layouts (cards stack cleanly, forms readable, buttons tappable).
- Subtle animations only (no distracting motion).
- Strong text/background contrast for readability.
- Professional commercial copy (no technical/security jargon in storefront UI).

## 5) Research integrity checklist

- Keep request logging middleware active in `store/middleware.py`.
- Keep deterministic classification rules active in `store/utils.py`.
- Keep analytics aggregation in `store/views.py` functional.
- Keep CSV export route and buttons working.

## 6) Safe workflow before/after edits

1. Run validation before changes:
   - `python manage.py check`
2. Make design edits.
3. Run validation again:
   - `python manage.py check`
4. Manual smoke test in browser:
   - Home, Shop, Product Details, Login/Register, Checkout
   - Fake admin (`/admin/`)
   - Research analytics (`/research/analytics/`)
   - CSV export links
5. Confirm logs are still being generated in analytics and CSV exports.

## 7) If you change models

1. Update models in `store/models.py`.
2. Run:
   - `python manage.py makemigrations`
   - `python manage.py migrate`
3. Re-test analytics and exports.

## 8) Common mistakes to avoid

- Putting inline styles everywhere instead of centralizing in `static/css/styles.css`.
- Renaming form fields without updating backend forms/views.
- Changing chart IDs in template without updating JavaScript.
- Hiding/removing decoy routes that attackers are expected to probe.
- Adding obvious security wording to customer-facing pages.
