# Institutional KYC for the onboarding scenario (research, Sun 4 Oct ~06:00)

What a bank needs to onboard **Northwind Capital Partners LP** (fictional), a Cayman Islands hedge fund opening a prime
brokerage and OTC derivatives relationship. The scenario in `demo/onboarding.py` follows this. Source tags: **[P]**
primary or authoritative, **[S]** secondary (law firm, vendor, press), **⚠** inference or still to confirm.

## Who the bank must identify
- A hedge fund set up as a **Cayman exempted limited partnership** has no separate legal personality; it **acts by its
  general partner** (GP). [Ogier, S; JMLSG Part II Sector 20.39, P]
- **US FinCEN CDD Rule** (31 CFR 1010.230): for a pooled investment vehicle the bank does **not** look through to the
  fund's investors; only the **control prong** applies: one individual who controls the fund (e.g. the portfolio
  manager behind the GP). A fund advised by an SEC-registered adviser is excluded from "legal entity customer"
  altogether. [FinCEN CDD FAQs May 2026 B.21, P]
- **UK/Cayman practice:** look through to investors only at a "relevant interest" (25%; Cayman regulated firms 10%);
  the **administrator** confirms investor due diligence in an **AML comfort letter**. [JMLSG 20.42–20.48, P]
- So the individuals in the file are the **principals behind the GP and the investment manager**: Elena Marsh (62%,
  control person) and Tomasz Wilk (25%), not "owners of the fund". Two investors at 62%/25% would make the fund a
  private investment vehicle, a higher-risk indicator. [JMLSG 20.17, P]

## Documents
| Document | Purpose | Standard / EDD |
|---|---|---|
| Certificate of registration (exempted limited partnership) | the fund exists | standard |
| Limited partnership agreement | GP powers, purpose | standard |
| Offering memorandum | strategy, investor eligibility, service providers | standard |
| CIMA certificate, Mutual Funds Act s.4(3) (open-ended funds; not the Private Funds Act) | regulatory status | standard |
| GP: certificate of incorporation, register of directors, certificate of incumbency | who acts for the fund | standard |
| Investment management agreement + manager's regulator (FCA or SEC) | who places the orders | standard |
| Ownership and control structure chart | beneficial ownership and control | standard |
| ID for principals, directors and signatories: name, date of birth, residential address, passport (with expiry) | CIP / CDD | standard |
| Authorised signatory list + GP board resolution | authority to trade | standard |
| Administrator AML comfort letter | basis for not KYC'ing investors directly | standard for funds |
| W-8IMY (fund taxed as a partnership) + FATCA GIIN | tax status | standard |
| LEI | required to trade and report derivatives | standard for trading |
| Audited financial statements | size, legitimacy | risk-based |
| Source of wealth of the principals, more on significant investors | evidence | **EDD** |

## Screening
- On **all parties**: the fund, the GP, the investment manager, GP directors, principals, authorised signatories.
  [Wolfsberg sanctions screening guidance, P]
- Matching uses **name + date of birth + nationality** (entities: name, jurisdiction, registration number). The
  **passport number resolves a possible match**; it is not the matching key. [Wolfsberg 4.2, 6.3; OFAC FAQ 5, P]
- Lists: OFAC SDN and non-SDN (50% rule), UN Security Council, EU consolidated list, **UK Sanctions List** (FCDO; the
  OFSI consolidated list closed on 28 Jan 2026 [S]). Plus PEP and adverse-media screening.

## Risk rating and sign-off
- Northwind as modelled: **medium** risk (Cayman fund, regulated manager, administrator letter, no PEPs). Cayman left
  the FATF grey list in Oct 2023 and the EU high-risk list in Feb 2024: do not call it high-risk. [S]
- EDD triggers: unregulated manager, concentrated investors, PEP or adverse media, withheld ownership information.
- Review cycle is risk-based (typical practice: 1 year high, 2–3 medium, 3–5 low). [S]
- The memo is drafted by the analyst (here: the agent) and approved by a human checker; Compliance approves high-risk
  or EDD cases. **The agent never approves the file.**

## Mistakes a banker would notice (avoided in the demo)
Fund investors listed as "UBOs"; Cayman called high-risk; the LP signing without its GP; a hedge fund under the Private
Funds Act; "HMT consolidated list"; screening by passport number alone; missing dates of birth, addresses or passport
expiry; GP, manager, directors or signatories not screened; W-8BEN-E for a partnership; no LEI for a derivatives client;
the agent approving the file. A real "Northwind Group" exists (New York real estate): the data is fictional.

Sources: FinCEN CDD FAQs (May 2026), 31 CFR 1010.230, JMLSG Part II Sector 20, Wolfsberg Guidance on Sanctions
Screening (2019), OFAC FAQ 5, FMSB client onboarding standard (2024 draft), IRS W-8IMY instructions, Ogier and Harneys
on Cayman funds, CIMA FAQs, Clifford Chance (FATF grey list), Loeb Smith (EU list), GOV.UK UK Sanctions List.
