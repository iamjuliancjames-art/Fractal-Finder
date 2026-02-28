# =============================================================================
#  Fractal Finder — Cognito Synthetica Guardrail (No dependencies)
#  Pattern detection + threat mitigation using:
#    - RoomStore tokens/novelty/pseudo_sim (perception)
#    - Seeker search (pattern search over documents/page results)
#    - Martian recall (symbiosis verification / context alignment)
#  Governance:
#    - quarantine (non-destructive) + audit log + safe pivot suggestions
# =============================================================================

class FractalFinder:
    """
    Threat mitigation layer (PFC analog).
    - Multi-scale feature extraction: tokens → ngrams → clauses → sliding windows.
    - Detection: sensitive vocab + controlled regex patterns + intent/target heuristics.
    - Governance: quarantine rooms (meta.quarantined/meta.archived), never delete.
    - Provenance: log decisions with evidence and room IDs.
    """

    DEFAULT_SENSITIVE = {
        # cyber abuse indicators (broad, customizable)
        "hack", "phish", "credential", "credentials", "steal", "bypass", "exploit", "malware",
        "ddos", "botnet", "ransomware", "keylogger", "backdoor", "sql injection", "xss",
        "unauthorized access", "crack", "payload", "trojan",
        # violence indicators (generic)
        "kill", "murder", "bomb", "poison", "weapon",
        # self-harm indicators (generic)
        "suicide", "self harm",
    }

    INTENT_MARKERS = {
        "how", "steps", "teach", "instructions", "guide", "make", "build", "write", "generate",
        "bypass", "break", "steal", "disable", "evade", "undetectable"
    }

    TARGET_MARKERS = {
        "account", "password", "email", "bank", "router", "wifi", "server", "system", "work",
        "phone", "device", "network", "website", "api", "database", "credentials"
    }

    def __init__(
        self,
        cognito,  # CognitoSynthetica
        hostile_patterns: Optional[List[str]] = None,
        sensitive_terms: Optional[Set[str]] = None,
        *,
        symbiosis_threshold: float = 0.65,
        novelty_threshold: float = 0.70,
        max_fragments: int = 260,
        ngram_max: int = 3,
        clause_max: int = 10,
        window_sizes: Tuple[int, ...] = (4, 6),
        quarantine_hits: int = 8,
        enable_symbiosis_check: bool = True,
        hard_block_on_explicit: bool = True,
    ):
        self.cs = cognito
        self.store = cognito.store

        self.sensitive_terms = set(sensitive_terms) if sensitive_terms else set(self.DEFAULT_SENSITIVE)
        self.hostile_patterns = hostile_patterns or []
        self.symbiosis_threshold = symbiosis_threshold
        self.novelty_threshold = novelty_threshold

        self.max_fragments = max_fragments
        self.ngram_max = max(2, min(ngram_max, 4))
        self.clause_max = clause_max
        self.window_sizes = window_sizes
        self.quarantine_hits = quarantine_hits

        self.enable_symbiosis_check = enable_symbiosis_check
        self.hard_block_on_explicit = hard_block_on_explicit

        self.audit_log: List[Dict] = []

        # Compile short regex patterns safely (controlled)
        self._compiled = []
        self._literal_patterns = []
        for p in self.hostile_patterns:
            if not isinstance(p, str) or not p:
                continue
            if len(p) > 64:
                # treat long patterns as literals to avoid regex risk
                self._literal_patterns.append(p.lower())
                continue
            try:
                self._compiled.append(re.compile(p, re.IGNORECASE))
            except re.error:
                self._literal_patterns.append(p.lower())

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────
    def guard_query(self, query: str) -> Dict[str, Any]:
        """
        Returns:
          {
            safe: bool,
            severity: none|low|med|high,
            action: allow|warn|redirect,
            reason: str,
            matches: [fragments],
            risk: float,
            signals: {...},
            quarantined_room_ids: [int],
            pivot: str|None
          }
        """
        query = (query or "").strip()
        if not query:
            return {"safe": True, "severity": "none", "action": "allow", "reason": "empty", "matches": [], "risk": 0.0, "signals": {}, "quarantined_room_ids": [], "pivot": None}

        frags = self._fractal_features(query)
        matches = self._detect_explicit(frags)

        # Explicit match → block/redirect (optionally quarantine related rooms)
        if matches and self.hard_block_on_explicit:
            quarantined = self._quarantine_related(matches)
            pivot = self._pivot(mode="explicit")
            out = {"safe": False, "severity": "high", "action": "redirect", "reason": "Sensitive/hostile pattern detected", "matches": matches, "risk": 1.0, "signals": {"evidence": "explicit"}, "quarantined_room_ids": quarantined, "pivot": pivot}
            self._audit("BLOCK", out, query)
            return out

        # Ambiguity risk model
        risk, signals = self._risk_model(query, frags)

        # If high risk, and symbiosis not verified → redirect
        if risk >= 0.75:
            ok = True
            if self.enable_symbiosis_check:
                ok = self._verify_symbiosis(signals.get("novel_frags", [])[:12])
            if not ok:
                pivot = self._pivot(mode="ambiguous")
                out = {"safe": False, "severity": "med", "action": "redirect", "reason": "Ambiguous high-risk request; not aligned with safe context", "matches": [], "risk": risk, "signals": signals, "quarantined_room_ids": [], "pivot": pivot}
                self._audit("WARN_BLOCK", out, query)
                return out

        # Mild risk → warn but allow
        if 0.45 <= risk < 0.75:
            pivot = self._pivot(mode="warn")
            out = {"safe": True, "severity": "low", "action": "warn", "reason": "Potentially sensitive ambiguity (low confidence)", "matches": [], "risk": risk, "signals": signals, "quarantined_room_ids": [], "pivot": pivot}
            self._audit("WARN", out, query)
            return out

        out = {"safe": True, "severity": "none", "action": "allow", "reason": "clear", "matches": [], "risk": risk, "signals": signals, "quarantined_room_ids": [], "pivot": None}
        return out

    def guard_room_ingest(self, canonical: str, kind: str) -> Dict[str, Any]:
        """
        Applies the same guard to *content being ingested* (docs/page results/memory).
        For ingestion, action can be:
          - allow
          - quarantine (store it but archived+quarantined)
        """
        d = self.guard_query(canonical)
        if not d["safe"] and d["severity"] in ("med", "high"):
            # For ingestion: we generally want quarantine rather than outright drop,
            # unless you explicitly choose to drop.
            d["action"] = "quarantine"
        d["signals"]["ingest_kind"] = kind
        return d

    # ──────────────────────────────────────────────────────────────────────────
    # Fractal features (bounded multi-scale perception)
    # ──────────────────────────────────────────────────────────────────────────
    def _fractal_features(self, text: str) -> List[str]:
        toks = self.store.tokens(text)
        frags: List[str] = []
        seen: Set[str] = set()

        def add(x: str):
            x = (x or "").strip().lower()
            if not x or x in seen:
                return
            seen.add(x)
            frags.append(x)

        # tokens
        for t in toks:
            add(t)
            if len(frags) >= self.max_fragments:
                return frags

        # ngrams
        for n in range(2, min(self.ngram_max + 1, len(toks) + 1)):
            for i in range(len(toks) - n + 1):
                add(" ".join(toks[i:i+n]))
                if len(frags) >= self.max_fragments:
                    return frags

        # clauses (non-recursive)
        clauses = re.split(r"[.;!?]", text)[: self.clause_max]
        for c in clauses:
            ct = self.store.tokens(c)
            if not ct:
                continue
            add(" ".join(ct[: min(10, len(ct))]))
            if len(frags) >= self.max_fragments:
                return frags

        # sliding windows (captures dispersed intent)
        for w in self.window_sizes:
            if len(toks) < w:
                continue
            for i in range(len(toks) - w + 1):
                add(" ".join(toks[i:i+w]))
                if len(frags) >= self.max_fragments:
                    return frags

        return frags

    # ──────────────────────────────────────────────────────────────────────────
    # Explicit detection
    # ──────────────────────────────────────────────────────────────────────────
    def _detect_explicit(self, frags: List[str]) -> List[str]:
        matches: List[str] = []

        # sensitive substring match (supports multiword like "sql injection")
        for f in frags:
            for term in self.sensitive_terms:
                if term in f:
                    matches.append(f)
                    break

        # compiled regex patterns
        for f in frags:
            for rx in self._compiled:
                if rx.search(f):
                    matches.append(f)

        # literal patterns
        for f in frags:
            fl = f.lower()
            for p in self._literal_patterns:
                if p in fl:
                    matches.append(f)

        # dedupe preserve order
        out = []
        seen = set()
        for m in matches:
            if m in seen:
                continue
            seen.add(m)
            out.append(m)
        return out

    # ──────────────────────────────────────────────────────────────────────────
    # Risk model: novelty + intent + target + sensitive vocab = risk
    # ──────────────────────────────────────────────────────────────────────────
    def _risk_model(self, query: str, frags: List[str]) -> Tuple[float, Dict[str, Any]]:
        ql = query.lower()
        novel_frags = [f for f in frags if self.store.novelty(f) >= self.novelty_threshold]

        has_intent = any(m in ql for m in self.INTENT_MARKERS)
        has_target = any(t in ql for t in self.TARGET_MARKERS)
        has_sensitive = any(s in ql for s in self.sensitive_terms)

        # combo emphasis
        combo = 0.0
        if has_intent and has_sensitive:
            combo = max(combo, 0.90)
        if has_sensitive and has_target:
            combo = max(combo, 0.80)
        if has_intent and has_target:
            combo = max(combo, 0.65)

        risk = 0.0
        if novel_frags:
            risk += 0.20
        if has_intent:
            risk += 0.25
        if has_target:
            risk += 0.15
        if has_sensitive:
            risk += 0.45

        risk = _clamp(max(risk, combo), 0.0, 1.0)

        signals = {
            "novelty": 1.0 if novel_frags else 0.0,
            "intent": 1.0 if has_intent else 0.0,
            "target": 1.0 if has_target else 0.0,
            "sensitive_vocab": 1.0 if has_sensitive else 0.0,
            "novel_frags": novel_frags[:24],
        }
        return risk, signals

    # ──────────────────────────────────────────────────────────────────────────
    # Symbiosis verification: secondary signal, never sole clearance
    # ──────────────────────────────────────────────────────────────────────────
    def _verify_symbiosis(self, nuances: List[str]) -> bool:
        if not nuances:
            return True

        # Use Martian recall as "safe alignment" check (secondary)
        for nuance in nuances:
            recalls = self.cs.recall(nuance, top_k=3)
            max_sim = 0.0
            for r in recalls or []:
                max_sim = max(max_sim, self.store.pseudo_sim(nuance, r.get("canonical", "")))
            if max_sim < self.symbiosis_threshold:
                return False
        return True

    # ──────────────────────────────────────────────────────────────────────────
    # Governance: quarantine related rooms (non-destructive)
    # ──────────────────────────────────────────────────────────────────────────
    def _quarantine_related(self, matches: List[str]) -> List[int]:
        quarantined: List[int] = []
        # Use Seeker search to find rooms related to matched fragments
        for m in matches[:12]:
            hits = self.cs.search(m, top_k=self.quarantine_hits, hops=1, diversify=False) or []
            for h in hits:
                rid = h.get("id")
                if rid is None:
                    continue
                rr = self.store.room_by_id(rid)
                if not rr:
                    continue
                rr["meta"]["archived"] = True
                rr["meta"]["quarantined"] = True
                quarantined.append(int(rid))

        # dedupe
        out = []
        seen = set()
        for rid in quarantined:
            if rid in seen:
                continue
            seen.add(rid)
            out.append(rid)
        return out

    def _pivot(self, mode: str) -> str:
        if mode == "explicit":
            return (
                "I can’t help with harmful or illicit requests. If your goal is legitimate safety, I *can* help with:\n"
                "- threat awareness and prevention\n"
                "- detection/monitoring\n"
                "- incident response checklists\n"
                "- secure design and auditing (authorized)\n"
                "Tell me what you’re trying to protect and your environment (device, web app, network)."
            )
        if mode == "ambiguous":
            return (
                "That reads as potentially risky/ambiguous. If you’re doing authorized defense/testing, reframe as:\n"
                "- “How do I harden X against Y?”\n"
                "- “How do I detect Y on X?”\n"
                "- “What’s the safe/legal way to assess my system?”\n"
                "Share the defensive objective and constraints."
            )
        return (
            "If you meant this for legitimate defense, clarify authorization and the defensive goal "
            "(prevention, detection, monitoring, remediation)."
        )

    def _audit(self, event: str, decision: Dict[str, Any], query: str):
        entry = {
            "ts": time.time(),
            "event": event,
            "safe": decision.get("safe"),
            "severity": decision.get("severity"),
            "action": decision.get("action"),
            "reason": decision.get("reason"),
            "risk": decision.get("risk"),
            "matches": decision.get("matches", [])[:30],
            "signals": decision.get("signals", {}),
            "quarantined_room_ids": decision.get("quarantined_room_ids", [])[:80],
        }
        # stable digest for audit
        s = f"{entry['event']}|{entry['severity']}|{entry['action']}|{entry['reason']}|{query}|{entry['risk']}|{entry['matches']}|{entry['quarantined_room_ids']}"
        entry["digest"] = hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]
        self.audit_log.append(entry)

    def audit_summary(self, last: int = 10) -> str:
        rows = self.audit_log[-last:]
        lines = [f"FractalFinder audit (last {len(rows)})"]
        for a in rows:
            t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["ts"]))
            lines.append(f"- {t} | {a['event']}/{a['severity']}/{a['action']} | {a['reason']} | digest={a['digest']}")
        return "\n".join(lines)
