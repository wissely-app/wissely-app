# WISSELY — Complete Business Summary
*Save this document. It contains everything built today.*

---

## THE BUSINESS

**Product Name:** Wissely
**Website:** wissely.com (ALREADY PURCHASED)
**Tagline:** Your business finances in plain English
**What it does:** AI tool that reads messy invoices, expenses and cash flow and explains them simply. No accountant needed.

---

## THE PRODUCT

**6 Tools built and working:**
1. Invoice Analyzer — reads any invoice, extracts all details
2. Expense Categorizer — sorts expenses for tax
3. Finance Reports — generates clear financial summaries
4. Payment Requests — writes follow-up emails for unpaid invoices
5. Fraud Detection — catches duplicate invoices and errors
6. Cash Flow Forecast — shows 30, 60, 90 day money picture

**Files created today:**
- wissely-landing.html — the full landing page
- invoiceai.jsx — the working AI product (needs rebranding to Wissely)

---

## PRICING

| Plan | Price | Features |
|------|-------|---------|
| Starter | $12/month | 50 analyses, all 6 tools |
| Pro | $29/month | Unlimited, exports, priority support |
| Business | $79/month | 10 seats, API access, integrations |

All plans include 14-day free trial. No credit card needed.

---

## TARGET MARKET

- Freelancers
- Small agencies
- Consultants
- Small business owners
- US and Europe (10 countries on landing page)

---

## TECH STACK

- Frontend: React JSX + HTML
- AI: Claude API (claude-sonnet-4-20250514)
- AI abstraction layer built — GPT4 and Gemini slots ready
- Payments: Stripe (not yet set up)
- Hosting: Vercel (free)
- Database: Supabase (free)
- Domain: wissely.com (purchased on Namecheap)

---

## AI ABSTRACTION LAYER

The code is built to swap AI models easily:

async function callAI(model, prompt) {
  if (model === "claude")  — works now
  if (model === "gpt4")    — plug in when revenue comes
  if (model === "gemini")  — plug in later
}

---

## ROADMAP

Phase 1 — NOW
- 6 AI finance tools (built)

Phase 2 — Q3 2026
- Financial history tracking
- Month on month trends
- PDF and image upload
- Multi-currency support

Phase 3 — Q4 2026
- Bank account connections
- QuickBooks sync
- Stripe integration
- Mobile app

Phase 4 — 2027
- Payment automation
- Tax filing
- Payroll management
- Enterprise API

---

## MARKETING PLAN

Week 1: Post on Reddit (r/smallbusiness, r/freelance, r/entrepreneur)
Week 2: Start LinkedIn daily posting
Week 3: Launch on Product Hunt
Week 4: First blog post for SEO
Month 2: Email outreach to freelancers
Month 3: First paid LinkedIn ad ($50)

Post template:
"I built a free tool that explains your business finances in plain English. No accountant needed. Would love honest feedback from small business owners."

---

## REVENUE PROJECTIONS

| Users | Plan | Monthly |
|-------|------|---------|
| 100 | Pro $29 | $2,900 |
| 500 | Pro $29 | $14,500 |
| 1000 | Pro $29 | $29,000 |

---

## NEXT STEPS IN ORDER

1. Get Claude API key from console.anthropic.com
2. Add $5 credit to Claude account
3. Deploy product to Vercel (vercel.com)
4. Connect wissely.com domain to Vercel
5. Set up Stripe payments
6. Add privacy policy (termly.io — free)
7. Share landing page on Reddit for first users
8. Get first 10 paying customers
9. Use revenue to add GPT-4 as second AI option
10. Keep building features from roadmap

---

## COMPETITORS AND OUR ADVANTAGE

Competitors: QuickBooks, Xero, Rillion, Basware
Their weakness: Built for accountants, complex, expensive ($45-79 per user)
Our advantage: Built for business owners, simple, cheap ($29 flat)

---

## WHY THIS IS EVERGREEN

- Businesses always exist
- Businesses always have invoices
- Businesses always want simple answers
- Market growing from $13.4B to $27.5B by 2034
- Laws forcing invoice automation in 80+ countries
- Once data is inside Wissely, customers never leave

---

## LANDING PAGE SECTIONS

The landing page (wissely-landing.html) contains:
1. Navigation with mobile menu
2. Hero section with stats
3. Live demo card showing real example
4. Trust strip with 5 signals
5. Country flags — 10 countries
6. 6 Features with Available Now badges
7. Before vs After comparison
8. Pricing — 3 tiers
9. Roadmap — 4 phases
10. 3 Testimonials (UK, US, Germany)
11. FAQ — 6 questions
12. Waitlist email capture
13. Footer with Privacy, Terms, GDPR links

Design colors:
- Dark: #0c0c0a
- Sage green: #2d4a3e
- Gold: #c9a84c
- Cream: #f8f6f0

---

## HOW TO CONTINUE IN A NEW CHAT

Paste this entire document into a new Claude chat and say:
"This is my Wissely SaaS business. Continue helping me build it."

Claude will understand everything instantly and pick up where we left off.

---

*Built in one day. Now go execute.*
*wissely.com — Your finances, finally clear.*
