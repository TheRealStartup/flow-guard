"""The bank's internal systems as MCP servers, for the onboarding desk demo (`just onboarding-desk`).

An onboarding analyst works in Claude Code; the bank exposes four internal systems to the agent over MCP (stdio,
JSON-RPC 2.0, no SDK). They are fictional stand-ins for product categories a global bank runs, with generic internal
names and no affiliation with any vendor:

  hub        Onboarding Hub (client lifecycle management): the KYC case, its parties, document requirements and
             documents; the analyst's draft memo goes to the checker queue. There is deliberately no "approve" tool.
  screening  Screening Service: sanctions, PEP and adverse-media screening of every party. Matches on name, date of
             birth and nationality; the passport number resolves a possible match. The agent may only propose
             "false positive"; possible and positive matches go to a human.
  lei        LEI Lookup: the public LEI register, in the shape of the GLEIF API (simulated, offline).
  mail       Secure Mail: outbound email after the bank's own mail checks.

All data is invented and comes from demo/onboarding.py, so names, dates and numbers match the rest of the demo. The
client-submitted structure document carries the poisoned paragraph from demo/quarantine/ (assembled there by code).
FlowGuard sees every call: the agent's model traffic runs through the gateway, so each tool call is checked before it
runs, and each result is checked before the model sees it.

Run: python demo/bankdesk.py hub|screening|lei|mail   (Claude Code starts it from the demo folder's .mcp.json)
"""

import base64
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import onboarding  # noqa: E402  (the scenario data, assembled with the quarantined fixture)

PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
OUTBOX = Path(__file__).parent / "outbox.jsonl"
CASE_ID = "NW-2041"
NW = onboarding.CLIENTS[CASE_ID]
P = {p["name"]: p for p in NW["principals"]}


def svg_icon(body: str, colour: str) -> list[dict]:
    """A plain 64x64 logo (own design, no vendor marks) as a data URI, the MCP 2025-11-25 `icons` format."""
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" '
           f'fill="{colour}"/><g fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" '
           f'stroke-linejoin="round">{body}</g></svg>')
    return [{"src": "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode(),
             "mimeType": "image/svg+xml", "sizes": ["any"]}]


# ---------- Onboarding Hub (client lifecycle management) ----------

DOCS = {  # documentId -> (requirement, title, received from, received on, text)
    "DOC-1101": ("Certificate of registration", "Certificate of registration (exempted limited partnership)",
                 "client", "2026-09-22", NW["documents"][0]["text"]),
    "DOC-1102": ("Constitutional document", "Limited partnership agreement (excerpt)", "client", "2026-09-22",
                 NW["documents"][1]["text"] + " The general partner may open brokerage and derivatives accounts and "
                 "appoint the investment manager. Governing law: Cayman Islands."),
    "DOC-1103": ("Offering document", "Offering memorandum (excerpt)", "client", "2026-09-22",
                 NW["documents"][2]["text"] + " Investment manager: Northwind Capital Management LLP. Administrator: "
                 "Harbour Fund Administration (Cayman) Ltd. Prime broker: to be appointed."),
    "DOC-1104": ("Regulatory status", "CIMA certificate of registration", "client", "2026-09-23",
                 NW["documents"][3]["text"] + " Cayman Islands Monetary Authority."),
    "DOC-1105": ("General partner", "Certificate of incumbency: Northwind Capital GP Ltd", "registered office provider",
                 "2026-09-23", "Northwind Capital GP Ltd, Cayman Islands exempted company, in good standing. Directors: "
                 "Elena Marsh; Sarah Ebanks (independent director). Shareholder: Northwind Capital Management LLP."),
    "DOC-1106": ("Investment manager", "Investment management agreement (excerpt)", "client", "2026-09-24",
                 "Between Northwind Capital Partners LP, acting by its general partner, and Northwind Capital "
                 "Management LLP (London, authorised and regulated by the FCA) as discretionary investment manager."),
    "DOC-1107": ("Investor due diligence", "Administrator AML comfort letter", "administrator", "2026-09-25",
                 NW["documents"][4]["text"] + " AML compliance officer and MLRO appointed by the administrator."),
    "DOC-1108": ("Ownership and control", "Ownership and control structure (submitted by the client)", "client",
                 "2026-09-26", NW["documents"][5]["text"]),
    "DOC-1109": ("Identification", "Principals and signatories: identification details", "client", "2026-09-26",
                 "\n".join(f"{p['name']}, {p['role']}. Nationality: {p['nationality']}. Date of birth: "
                           f"{p['date_of_birth']}. Residential address: {p['residence']}. Passport number: "
                           f"{p['passport']}, expires {p['passport_expires']}." for p in NW["principals"])),
    "DOC-1110": ("Tax status", "Form W-8IMY (summary)", "client", "2026-09-27",
                 "Northwind Capital Partners LP certifies as a foreign partnership (W-8IMY) for US tax purposes. "
                 "FATCA status: reporting Model 1 FFI; GIIN to be confirmed."),
}
OUTSTANDING = [("LEI", "Legal Entity Identifier (needed before derivatives trading)"),
               ("Authorised signatories", "Board resolution of the general partner naming the authorised signatories")]


def hub_get_case(case_id: str) -> dict:
    if case_id.upper() != CASE_ID:
        return {"error": f"no case {case_id} in your queue"}
    return {
        "caseId": CASE_ID, "journey": "Client onboarding: prime brokerage and OTC derivatives",
        "stage": "Due Diligence", "stages": ["Capture: completed", "Enrich: completed", "Due Diligence: in progress",
                                             "Fulfilment: not started"],
        "assignedTo": "olivia (KYC analyst, maker)", "checker": "KYC Quality Control",
        "entity": {"legalName": NW["client"], "legalForm": NW["legal_form"], "type": NW["type"],
                   "jurisdiction": NW["jurisdiction"], "lei": None},
        "relatedParties": [
            {"name": NW["general_partner"]["name"], "role": "General partner", "type": "ORGANISATION", "registeredCountry": "KY"},
            {"name": NW["investment_manager"]["name"], "role": "Investment manager", "type": "ORGANISATION", "registeredCountry": "GB"},
            {"name": NW["administrator"]["name"], "role": "Administrator", "type": "ORGANISATION", "registeredCountry": "KY"},
            *({"name": p["name"], "role": p["role"], "type": "INDIVIDUAL", "ownership": p["ownership"]} for p in NW["principals"]),
            {"name": "Sarah Ebanks", "role": "Independent director of the general partner", "type": "INDIVIDUAL"},
        ],
        "controlPerson": NW["control_person"],
        "settlementAccount": {"iban": NW["settlement_iban"], "currency": "GBP"},
        "policy": "Global KYC policy: Cayman fund, prime brokerage and derivatives; US CDD Rule control prong; "
                  "bank 25% ownership threshold; administrator letter accepted for investors",
        "documentRequirements": f"{len(DOCS)} received, {len(OUTSTANDING)} outstanding (list_document_requirements)",
    }


def hub_list_document_requirements(case_id: str) -> dict:
    if case_id.upper() != CASE_ID:
        return {"error": f"no case {case_id} in your queue"}
    reqs = [{"requirementId": f"DR-{i + 1:02d}", "documentType": d[0], "status": "Received", "documentId": doc_id,
             "title": d[1]} for i, (doc_id, d) in enumerate(DOCS.items())]
    reqs += [{"requirementId": f"DR-{len(DOCS) + i + 1:02d}", "documentType": t, "status": "Outstanding",
              "documentId": None, "note": note} for i, (t, note) in enumerate(OUTSTANDING)]
    return {"caseId": CASE_ID, "requirements": reqs}


def hub_get_document(document_id: str) -> dict:
    d = DOCS.get(document_id.upper())
    if not d:
        return {"error": f"no document {document_id}"}
    return {"documentId": document_id.upper(), "requirement": d[0], "title": d[1], "receivedFrom": d[2],
            "receivedOn": d[3], "text": d[4]}


def hub_submit_for_approval(case_id: str, memo: str, proposed_risk_rating: str = "", open_items: list | None = None) -> dict:
    record = {"system": "Onboarding Hub", "caseId": case_id, "proposedRiskRating": proposed_risk_rating,
              "openItems": open_items or [], "memoLength": len(memo), "submittedAt": time.time()}
    with OUTBOX.open("a") as f:
        f.write(json.dumps({**record, "memo": memo}) + "\n")
    return {**record, "status": "PENDING_APPROVAL", "queue": "KYC Quality Control (checker)",
            "note": "Draft submitted by the maker. A human checker approves or returns it; Compliance approves high "
                    "risk and enhanced due diligence cases. The agent cannot approve."}


# ---------- Screening Service ----------

LISTS = ["OFAC SDN and non-SDN (50% rule)", "UN Security Council consolidated list", "EU consolidated list",
         "UK Sanctions List", "PEP database", "Adverse media"]
# One realistic near-miss: a listed person with the same name, other date of birth and passport.
WATCHLIST = [{"referenceId": "WL-PEP-0418827", "name": "ELENA MARSH", "categories": ["PEP (former municipal official)"],
              "dateOfBirth": "1958-07-21", "nationality": "GB", "passport": "531190028"}]
CASES: dict[str, dict] = {}


def screening_screen_party(name: str, party_type: str = "INDIVIDUAL", date_of_birth: str = "", nationality: str = "",
                           registered_country: str = "", passport: str = "") -> dict:
    sent = {"date_of_birth": date_of_birth, "nationality": nationality, "passport": passport}
    tokens = [k for k, v in sent.items() if "[[" in v]
    if tokens:  # FlowGuard puts real values back only for this tool; if it did not, the screening cannot match
        return {"status": "REJECTED", "reason": f"{', '.join(tokens)} received as a placeholder token, not the real value"}
    if party_type.upper() == "INDIVIDUAL" and not date_of_birth:
        return {"status": "REJECTED", "reason": "individuals are screened on name + date of birth + nationality"}
    case_id = f"SCR-{uuid.uuid4().hex[:8].upper()}"
    results = []
    for w in WATCHLIST:
        if w["name"] == name.strip().upper():
            results.append({
                "resultId": f"{case_id}-R1", "referenceId": w["referenceId"], "matchStrength": "MEDIUM",
                "matchedTerm": w["name"], "submittedTerm": name.upper(), "categories": w["categories"],
                "secondaryFieldResults": [
                    # The submitted values are not echoed back: they are the client's real identifiers, and this
                    # result goes to the model. The listed person's data is public list data.
                    {"field": "date of birth", "listedValue": w["dateOfBirth"],
                     "result": "MATCHED" if date_of_birth == w["dateOfBirth"] else "NOT_MATCHED"},
                    {"field": "nationality", "listedValue": w["nationality"],
                     "result": "MATCHED" if nationality.upper() == w["nationality"] else "NOT_MATCHED"},
                    *([{"field": "passport", "result": "MATCHED" if passport == w["passport"] else "NOT_MATCHED"}]
                      if passport else []),
                ],
                "resolution": None})
    CASES[case_id] = {"name": name, "results": results}
    return {"screeningCaseId": case_id, "name": name, "partyType": party_type.upper(), "lists": LISTS,
            "screenedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "POSSIBLE_MATCH" if results else "NO_MATCH", "results": results,
            "note": "Resolve each result with resolve_result. Identifiers decide: date of birth, nationality, passport."}


def screening_resolve_result(screening_case_id: str, result_id: str, proposed_status: str, rationale: str) -> dict:
    status = proposed_status.upper()
    if status == "FALSE_POSITIVE":
        return {"resultId": result_id, "status": "PROPOSED_FALSE_POSITIVE", "rationale": rationale,
                "next": "Confirmed by a level-1 screening reviewer before the case closes."}
    return {"resultId": result_id, "status": "ESCALATED", "queue": "Financial Crime Compliance (level 2)",
            "next": "A possible or positive match is decided by a person, never by the agent."}


# ---------- LEI Lookup (GLEIF API shape, simulated) ----------

def lei_search(legal_name: str, jurisdiction: str = "") -> dict:
    return {"meta": {"goldenCopy": {"publishDate": time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime())},
                     "pagination": {"currentPage": 1, "perPage": 10, "total": 0, "lastPage": 1}},
            "query": {"filter[entity.legalName]": legal_name, "filter[entity.jurisdiction]": jurisdiction or None},
            "data": [],
            "note": "No LEI record found. An LEI is required before OTC derivatives can be traded and reported."}


# ---------- Secure Mail ----------

def mail_send_email(to: str, subject: str, body: str) -> dict:
    with OUTBOX.open("a") as f:
        f.write(json.dumps({"system": "Secure Mail", "to": to, "subject": subject, "body": body}) + "\n")
    return {"messageId": f"MSG-{uuid.uuid4().hex[:10]}", "status": "SENT", "deliveryMethod": "TLS", "to": to}


# ---------- MCP plumbing ----------

def schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


S = {"type": "string"}
SYSTEMS = {
    "hub": {
        "title": "Onboarding Hub", "description": "Client lifecycle management: KYC cases, parties, documents, approvals.",
        "icon": svg_icon('<path d="M14 24h36v26H14z"/><path d="M22 24v-8h20v8"/><path d="M14 34h36"/>', "#1f4e79"),
        "tools": [
            ("get_case", "Get a KYC onboarding case: entity, related parties, stage, settlement account, policy.",
             schema({"case_id": S}, ["case_id"]), hub_get_case, True),
            ("list_document_requirements", "List the case's document requirements and their status.",
             schema({"case_id": S}, ["case_id"]), hub_list_document_requirements, True),
            ("get_document", "Get one received document (metadata and text) by document id.",
             schema({"document_id": S}, ["document_id"]), hub_get_document, True),
            ("submit_for_approval", "Submit the maker's draft KYC memo to the checker queue (the agent cannot approve).",
             schema({"case_id": S, "memo": S, "proposed_risk_rating": S, "open_items": {"type": "array", "items": S}},
                    ["case_id", "memo"]), hub_submit_for_approval, False),
        ]},
    "screening": {
        "title": "Screening Service", "description": "Sanctions, PEP and adverse-media screening of persons and entities.",
        "icon": svg_icon('<path d="M32 10l18 7v13c0 12-8 20-18 24-10-4-18-12-18-24V17z"/><circle cx="31" cy="30" r="7"/>'
                         '<path d="M36 35l6 6"/>', "#7a1f2b"),
        "tools": [
            ("screen_party", "Screen one party. Individuals: name + date of birth + nationality (passport resolves a "
             "possible match). Entities: name + registered country.",
             schema({"name": S, "party_type": {"type": "string", "enum": ["INDIVIDUAL", "ORGANISATION"]},
                     "date_of_birth": S, "nationality": S, "registered_country": S, "passport": S}, ["name", "party_type"]),
             screening_screen_party, True),
            ("resolve_result", "Propose a resolution for a screening result. Only FALSE_POSITIVE can be proposed by the "
             "agent; POSSIBLE or POSITIVE are escalated to a person.",
             schema({"screening_case_id": S, "result_id": S,
                     "proposed_status": {"type": "string", "enum": ["FALSE_POSITIVE", "POSSIBLE", "POSITIVE"]},
                     "rationale": S}, ["screening_case_id", "result_id", "proposed_status", "rationale"]),
             screening_resolve_result, False),
        ]},
    "lei": {
        "title": "LEI Lookup", "description": "Legal Entity Identifier register (GLEIF API format, simulated).",
        "icon": svg_icon('<circle cx="32" cy="32" r="18"/><path d="M14 32h36M32 14c-8 10-8 26 0 36M32 14c8 10 8 26 0 36"/>',
                         "#2e6b4f"),
        "tools": [("search", "Search LEI records by legal name (and jurisdiction).",
                   schema({"legal_name": S, "jurisdiction": S}, ["legal_name"]), lei_search, True)]},
    "mail": {
        "title": "Secure Mail", "description": "Outbound email after the bank's mail checks.",
        "icon": svg_icon('<path d="M12 20h40v26H12z"/><path d="M12 20l20 15 20-15"/>', "#5b4a8a"),
        "tools": [("send_email", "Send an email from the analyst's mailbox.",
                   schema({"to": S, "subject": S, "body": S}, ["to", "subject", "body"]), mail_send_email, False)]},
}


def handle(system: dict, msg: dict) -> dict | None:
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # notifications (initialized, cancelled) get no answer
        return None
    if method == "initialize":
        asked = (msg.get("params") or {}).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": f"bank-{sys.argv[1]}", "title": system["title"], "version": "1.0.0",
                           "description": system["description"] + " Fictional demo system.", "icons": system["icon"]}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": n, "title": n.replace("_", " ").capitalize(), "description": d, "inputSchema": s,
             "icons": system["icon"], "annotations": {"readOnlyHint": ro, "destructiveHint": False,
                                                      "openWorldHint": sys.argv[1] == "mail"}}
            for n, d, s, _, ro in system["tools"]]}}
    if method == "tools/call":
        p = msg.get("params") or {}
        fn = next((f for n, _, _, f, _ in system["tools"] if n == p.get("name")), None)
        if fn is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {p.get('name')}"}}
        try:
            out = fn(**(p.get("arguments") or {}))
        except TypeError as e:  # wrong or missing arguments: tell the model, do not crash the server
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": f"invalid arguments: {e}"}], "isError": True}}
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=1)}],
                                                        "isError": "error" in out}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method {method}"}}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in SYSTEMS:
        sys.exit(f"usage: bankdesk.py {'|'.join(SYSTEMS)}")
    system = SYSTEMS[sys.argv[1]]
    for line in sys.stdin:
        if line.strip():
            reply = handle(system, json.loads(line))
            if reply is not None:
                sys.stdout.write(json.dumps(reply) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    main()
