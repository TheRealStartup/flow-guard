# Candidate signatures: verified incidents (research, Sun 4 Oct ~05:00)

Real, recent attacks on AI agents and ML supply chains that a signature on agent traffic could catch. Collected by a
research agent from primary or reputable sources. **Patterns are not written yet**: whoever writes them adds each to
`feeds/signatures.json` with `examples` (`match` / `no_match`); the gateway rejects any signature that misses its own
examples. Dates are NVD publication dates unless marked otherwise.

| Topic | CVE | Date | What to look for in agent traffic | Sources |
|---|---|---|---|---|
| Keras safe_mode bypass | CVE-2025-9906 | 2025-09-19 | unsafe deserialization switched on, or `load_model(..., safe_mode=False)`; fixed in Keras 3.11.0 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-9906), [GHSA](https://github.com/advisories/GHSA-36fq-jgmw-4r9c) |
| Keras config.json module injection | CVE-2025-1550 | 2025-03-11 | a `.keras` config naming an arbitrary Python module/function; fixed in 3.9.0 | [write-up](https://towerofhanoi.it/writeups/cve-2025-1550/) |
| GitHub Copilot "YOLO mode" | CVE-2025-53773 | 2025-08-12 | agent writes `"chat.tools.autoApprove": true` into `.vscode/settings.json` | [Embrace the Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) |
| Cursor CurXecute | CVE-2025-54135 | 2025-08-05 | agent writes to `.cursor/mcp.json`; fixed in 1.3.9 | [Cato](https://www.catonetworks.com/blog/curxecute-rce/), [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison) |
| Cursor MCPoison | CVE-2025-54136 | 2025-08-02 | the command of an approved `mcp.json` entry is swapped later | [Check Point](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/) |
| mcp-remote | CVE-2025-6514 | 2025-07-09 | OAuth `authorization_endpoint` from an MCP server that is not a plain https URL; fixed in 0.1.16 | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-6514/) |
| MCP Inspector | CVE-2025-49596 | 2025-06-13 | requests to `0.0.0.0:6277/sse?transportType=stdio&command=`; fixed in 0.14.1 | [The Hacker News](https://thehackernews.com/2025/07/critical-vulnerability-in-anthropics.html) |
| Langflow | CVE-2025-3248 | 2025-04 (unverified day) | POST to `/api/v1/validate/code`; in CISA's exploited list since 2025-05-05 | [Trend Micro](https://www.trendmicro.com/en_us/research/25/f/langflow-vulnerability-flodric-botnet.html) |
| Amazon Q extension wiper | CVE-2025-8217 | 2025-07-30 | destructive `aws` CLI calls and recursive deletes of the home directory | [AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/) |
| s1ngularity (Nx on npm) | — | 2025-08-26 | malware runs local AI coding CLIs with approvals switched off; appends shutdown to shell rc files | [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware), [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack) |
| Shai-Hulud npm worm | — | 2025-09-15 | postinstall running `bundle.js`, secret scanning with trufflehog, `shai-hulud-workflow.yml` | [CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) |
| postmark-mcp | — | 2025-09-17 | first malicious MCP server in the wild (hidden BCC); argues for flagging unpinned `npx -y …-mcp` | [The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) |
| Gemini CLI (Tracebit) | — | 2025-07-25 | allowlisted command followed by `;` and an environment dump sent out | [BleepingComputer](https://www.bleepingcomputer.com/news/security/flaw-in-gemini-cli-ai-coding-assistant-allowed-stealthy-code-execution/) |
| Claude Code echo bypass | CVE-2025-54795 | 2025-08 | command injection through a quoted `echo`; fixed in 1.0.20 | [Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/) |
| Replit agent deleted a production DB | — | 2025-07-18 | destructive SQL from an agent (`DROP` / `TRUNCATE` / `DELETE` without `WHERE`) | [The Register](https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident/) |
| Hallucinated packages ("slopsquatting") | — | 2024-03 | `pip install huggingface-cli` (the real one is `huggingface_hub[cli]`) | [overview](https://en.wikipedia.org/wiki/Slopsquatting) |
| Ultralytics PyPI compromise | — | 2024-12-04 | pins to ultralytics 8.3.41 / 8.3.42 (cryptominer) | [Wiz](https://www.wiz.io/blog/ultralytics-ai-library-hacked-via-github-for-cryptomining) |
| nullifAI models on Hugging Face | — | 2025-02-06 | 7z-compressed PyTorch pickles that evaded Picklescan | [ReversingLabs](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face) |
| LangGrinch (LangChain) | CVE-2025-68664 | 2025-12-23 | data carrying LangChain's reserved `"lc"` key with `"type": "secret"`; fixed in 0.3.81 / 1.2.5 | [The Hacker News](https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html) |
| EchoLeak (M365 Copilot) | CVE-2025-32711 | 2025-06 (unverified day) | reference-style markdown image/link definitions to URLs with query strings | [paper](https://arxiv.org/html/2509.10540v1) |
| ForcedLeak (Agentforce) | — | 2025-09-25 | exfiltration through an `img` URL on an expired, still-allowlisted domain | [The Register](https://www.theregister.com/software/2025/09/26/salesforce-agentforce-tricked-into-leaking-sales-leads/668952) |
| ShadowRay 2.0 | CVE-2023-48022 | 2025-11 | POSTs to `/api/jobs/` with an `entrypoint` running curl or bash (already covered by SIG-SHADOWRAY) | [Oligo](https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet) |
