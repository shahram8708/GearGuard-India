from __future__ import annotations

import json
import logging
import os
from datetime import datetime
import time
import socket
from typing import Any, Iterable

from google import genai

from app.models import Equipment, MaintenanceRequest, MaintenanceStatus, RequestType, User

logger = logging.getLogger(__name__)


class AIService:
    """Thin orchestrator around GearGuard India for maintenance intelligence."""

    def __init__(self) -> None:
        self._api_key = os.getenv("GENAI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("AI_API_KEY")
        self._client: genai.Client | None = None
        self._fallback_enabled = os.getenv("GENAI_ENABLE_FALLBACK", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self._did_diagnose = False
        raw_timeout = os.getenv("GENAI_HTTP_TIMEOUT", os.getenv("GENAI_TIMEOUT", None))
        # Default: do not set any timeout (let client/default/socket decide)
        self._timeout_seconds: int | None = None
        if raw_timeout is not None:
            if str(raw_timeout).strip().lower() in {"0", "none", "no", "off", "disable", "disabled"}:
                self._timeout_seconds = None
            else:
                self._timeout_seconds = int(raw_timeout)
        self._proxy = os.getenv("GENAI_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        if self._api_key:
            # Required structure: from  import genai; client = genai.Client()
            http_options: dict[str, Any] = {}
            if self._timeout_seconds is not None:
                http_options["timeout"] = self._timeout_seconds
            # Note: genai HttpOptions is strict; unsupported keys (like verify) raise ValidationError.
            # If proxy support is added upstream, supply via environment (HTTPS_PROXY/HTTP_PROXY).
            self._client = genai.Client(api_key=self._api_key, http_options=http_options)
            msg = (
                f"[GearGuard India] client initialized | timeout={self._timeout_seconds if self._timeout_seconds is not None else 'default'} | "
                f"proxy_env_present={bool(self._proxy)} | api_key_present={bool(self._api_key)}"
            )
            logger.info(msg)
            print(msg)
        else:
            logger.warning("Google GearGuard India API key missing. Set GENAI_API_KEY or GOOGLE_API_KEY.")

    def _client_or_raise(self) -> genai.Client:
        if not self._client:
            raise RuntimeError("AI is unavailable because the GearGuard India API key is not configured.")
        return self._client

    def _generate(self, prompt: str) -> str:
        client = self._client_or_raise()
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                start = time.perf_counter()
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                )
                elapsed = time.perf_counter() - start
                text = (response.text or "").strip()
                if not text:
                    raise RuntimeError("GearGuard India returned an empty response.")
                success_msg = (
                    f"[GearGuard India] success attempt={attempt + 1} elapsed={elapsed:.2f}s "
                    f"timeout={self._timeout_seconds}s proxy_env_present={bool(self._proxy)}"
                )
                logger.info(success_msg)
                print(success_msg)
                return text
            except Exception as exc:  # pragma: no cover - runtime safety
                last_err = exc
                elapsed = time.perf_counter() - start if 'start' in locals() else 0.0
                fail_msg = (
                    f"[GearGuard India] fail attempt={attempt + 1} elapsed={elapsed:.2f}s "
                    f"timeout={self._timeout_seconds}s proxy_env_present={bool(self._proxy)} error={exc}"
                )
                logger.exception(fail_msg)
                print(fail_msg)
                if not self._did_diagnose:
                    self._diagnose_connectivity()
                    self._did_diagnose = True
        raise last_err or RuntimeError("GearGuard India generation failed.")

    def _diagnose_connectivity(self) -> None:
        host = "generativelanguage.googleapis.com"
        try:
            ip = socket.gethostbyname(host)
            msg = f"[GearGuard India][diag] DNS resolved {host} -> {ip}"
            logger.info(msg)
            print(msg)
        except Exception as exc:
            msg = f"[GearGuard India][diag] DNS failed for {host}: {exc}"
            logger.error(msg)
            print(msg)
            return

        try:
            start = time.perf_counter()
            with socket.create_connection((host, 443), timeout=5):
                elapsed = time.perf_counter() - start
                msg = f"[GearGuard India][diag] TCP 443 connect OK in {elapsed:.2f}s to {host}"
                logger.info(msg)
                print(msg)
        except Exception as exc:
            msg = f"[GearGuard India][diag] TCP 443 connect failed to {host}: {exc}"
            logger.error(msg)
            print(msg)

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        trimmed = text.strip()
        if trimmed.startswith("```") and trimmed.endswith("```"):
            trimmed = trimmed[3:-3].strip()
        if trimmed.lower().startswith("json"):
            trimmed = trimmed[4:].strip()
        return trimmed

    def predictive_recommendations(self, equipment: Equipment, history: Iterable[MaintenanceRequest]) -> dict[str, Any]:
        history_materialized = list(history)
        history_payload = [
            {
                "id": req.id,
                "subject": req.subject,
                "status": req.status.value,
                "type": req.request_type.value,
                "priority": req.priority,
                "scheduled_date": req.scheduled_date.isoformat() if req.scheduled_date else None,
                "started_at": req.started_at.isoformat() if req.started_at else None,
                "completed_at": req.completed_at.isoformat() if req.completed_at else None,
                "duration_hours": req.duration_hours,
                "overdue": req.is_overdue,
            }
            for req in history_materialized
        ]

        prompt = (
            "You are an experienced reliability engineer for industrial maintenance. "
            "Use the provided structured data only. No invented facts. Avoid placeholders. "
            "Return JSON ONLY and nothing else. Required schema: "
            "{\"probability\": \"72%\", \"preventive_actions\": [\"action\"], "
            "\"risk_level\": \"low|medium|high|critical\", \"frequency\": \"cadence\", "
            "\"guidance\": [\"guidance\"], \"narrative\": \"under 160 words\"}. "
            "Example JSON: {\"probability\":\"68%\",\"preventive_actions\":[\"Inspect seals weekly\"],\"risk_level\":\"high\",\"frequency\":\"Increase PM to bi-weekly\",\"guidance\":[\"Stage parts ahead\"],\"narrative\":\"Pump shows rising failures; increase PM cadence and monitor vibration.\"}. "
            "If data is insufficient, return best-effort with clear assumptions."
            f"\nEquipment Context: {json.dumps(self._equipment_snapshot(equipment), default=str)}"
            f"\nHistory: {json.dumps(history_payload, default=str)}"
            "\nRespond in JSON only."  # explicitly reinforce JSON-only to reduce model hesitation
        )

        start_msg = (
            f"[GearGuard India] predictive start | equipment_id={equipment.id} | history_count={len(history_materialized)} | "
            f"timeout={self._timeout_seconds}s | proxy_env_present={bool(self._proxy)}"
        )
        logger.info(start_msg)
        print(start_msg)

        try:
            raw = self._generate(prompt)
        except Exception as exc:  # pragma: no cover - runtime safety
            logger.error("GearGuard India unavailable (no fallback): %s", exc)
            raise

        try:
            parsed = json.loads(self._strip_code_fence(raw))
            return parsed
        except json.JSONDecodeError:
            logger.error("GearGuard India predictive response was not JSON and fallback disabled: %s", raw)
            print(f"[GearGuard India] raw non-JSON response: {raw}")
            raise RuntimeError("GearGuard India returned a non-JSON response")

    def _fallback_recommendation(
        self,
        equipment: Equipment,
        history: list[MaintenanceRequest],
        *,
        error: str,
    ) -> dict[str, Any]:
        total = len(history)
        open_like = sum(1 for req in history if req.status in {MaintenanceStatus.NEW, MaintenanceStatus.IN_PROGRESS})
        overdue = sum(1 for req in history if getattr(req, "is_overdue", False))
        recent = sorted(history, key=lambda r: r.created_at or datetime.min, reverse=True)[:3]

        risk = "low"
        if overdue >= 2 or open_like >= 3:
            risk = "high"
        elif overdue == 1 or open_like >= 1:
            risk = "medium"

        probability = "80%" if risk == "high" else "55%" if risk == "medium" else "30%"

        preventive_actions = [
            "Review PM schedule and close overdue items",
            "Verify spares for next service window",
        ]
        if equipment.maintenance_team:
            preventive_actions.append(f"Align plan with team {equipment.maintenance_team.team_name}")

        freq = "Keep current cadence"
        if risk == "high":
            freq = "Increase inspections to weekly"
        elif risk == "medium":
            freq = "Bi-weekly checks recommended"

        recent_ids = [req.id for req in recent]

        return {
            "probability": probability,
            "preventive_actions": preventive_actions,
            "risk_level": risk,
            "frequency": freq,
            "guidance": [
                f"Heuristic fallback used because AI failed: {error}",
                f"Open/in-progress: {open_like}, overdue: {overdue}, total history: {total}",
                f"Most recent request IDs: {recent_ids}" if recent_ids else "No recent requests available",
            ],
            "narrative": (
                f"AI service unreachable; using rule-based guidance for {equipment.name}. "
                f"Risk looks {risk} with {overdue} overdue and {open_like} active items out of {total}."
            ),
        }

    def recommend_technician(self, request: MaintenanceRequest, technicians: list[dict[str, Any]], history: list[MaintenanceRequest]) -> dict[str, Any]:
        history_payload = [
            {
                "id": req.id,
                "status": req.status.value,
                "type": req.request_type.value,
                "priority": req.priority,
                "duration_hours": req.duration_hours,
                "assigned": req.assigned_technician.name if req.assigned_technician else None,
                "team": req.team.team_name if req.team else None,
            }
            for req in history
        ]
        prompt = (
            "You are an AI dispatcher. Choose the best technician for this maintenance request. "
            "Use only provided data. Do not invent. Return JSON ONLY with keys: "
            "{\"technician_id\": int, \"name\": string, \"reasoning\": string under 120 words, \"confidence\": \"low|medium|high\"}. "
            "Example JSON: {\"technician_id\":12,\"name\":\"Alex Kim\",\"reasoning\":\"Alex closed similar hydraulic leaks 30% faster and is free now.\",\"confidence\":\"high\"}. "
            "Favor technicians with matching team, lower open load, faster avg duration, and relevant history. "
            f"Request: {json.dumps(self._request_snapshot(request), default=str)}\n"
            f"Candidates: {json.dumps(technicians, default=str)}\n"
            f"Historical Requests: {json.dumps(history_payload, default=str)}"
        )
        raw = self._generate(prompt)
        cleaned = self._strip_code_fence(raw)
        try:
            parsed = json.loads(cleaned)
            # Normalize expected fields in case the model omits them.
            if not isinstance(parsed, dict):
                raise json.JSONDecodeError("Expected object", cleaned, 0)
            return {
                "technician_id": parsed.get("technician_id"),
                "name": parsed.get("name"),
                "reasoning": parsed.get("reasoning", ""),
                "confidence": parsed.get("confidence", ""),
            }
        except json.JSONDecodeError:
            logger.warning("GearGuard India technician response not JSON; wrapping raw text.")
            return {"technician_id": None, "name": None, "reasoning": cleaned, "confidence": ""}

    def enhance_description(
        self,
        *,
        subject: str,
        description: str,
        equipment: Equipment | None,
        request_type: RequestType,
        priority: str,
    ) -> str:
        prompt = (
            "Rewrite the maintenance request description to be crisp, structured, and actionable. "
            "Sections: 1) Summary (1-2 sentences) 2) Likely causes (short sentences) 3) Immediate checks (short sentences). "
            "Under 140 words. No new facts. Use equipment/request context only. Output plain text only — no markdown, no bullets, no numbered lists. Separate lines with newline characters.\n"
            f"Subject: {subject}\n"
            f"Raw Description: {description}\n"
            f"Equipment: {json.dumps(self._equipment_snapshot(equipment) if equipment else {}, default=str)}\n"
            f"Request Type: {request_type.value}\nPriority: {priority}"
        )
        return self._generate(prompt)

    def ai_insights_panel(self, organization_name: str, summary: dict[str, Any]) -> dict[str, Any]:
        prompt = (
            "You are an AI maintenance strategist. Generate concise insights for the dashboard. "
            "Return JSON ONLY with keys: {\"top_risk\": [string,...], \"likely_break\": [string,...], \"efficiency\": [string,...], \"ops\": [string,...]}. "
            "Max 5 items per list. Each item must include an action or observation. No placeholders. "
            "Example JSON: {\"top_risk\":[\"Press A has 3 overdue PMs; schedule within 48h\"],\"likely_break\":[\"Chiller 2 shows repeat leaks; monitor pressure daily\"],\"efficiency\":[\"Standardize torque specs to cut rework\"],\"ops\":[\"Pre-stage seals for night shift\"]}. "
            f"Organization: {organization_name}\nContext: {json.dumps(summary, default=str)}"
        )
        raw = self._generate(prompt)
        cleaned = self._strip_code_fence(raw)

        def _as_list(value: Any) -> list[str]:
            if isinstance(value, list):
                return [str(item) for item in value]
            if value is None:
                return []
            return [str(value)]

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("GearGuard India insights response not JSON; using fallback text block.")
            parsed = {
                "top_risk": [cleaned],
                "likely_break": [],
                "efficiency": [],
                "ops": [],
            }

        # Normalize structure in case the model omits keys or returns scalars.
        return {
            "top_risk": _as_list(parsed.get("top_risk")),
            "likely_break": _as_list(parsed.get("likely_break")),
            "efficiency": _as_list(parsed.get("efficiency")),
            "ops": _as_list(parsed.get("ops")),
        }

    @staticmethod
    def _equipment_snapshot(equipment: Equipment) -> dict[str, Any]:
        return {
            "id": equipment.id,
            "name": equipment.name,
            "category": equipment.category,
            "status": equipment.status.value,
            "location": equipment.location,
            "team": equipment.maintenance_team.team_name if equipment.maintenance_team else None,
            "assigned_to": equipment.assigned_to_user.name if equipment.assigned_to_user else None,
        }

    @staticmethod
    def _request_snapshot(request: MaintenanceRequest) -> dict[str, Any]:
        return {
            "id": request.id,
            "subject": request.subject,
            "type": request.request_type.value,
            "priority": request.priority,
            "equipment": request.equipment.name if request.equipment else None,
            "team": request.team.team_name if request.team else None,
            "status": request.status.value,
            "overdue": request.is_overdue,
        }

ai_service = AIService()

__all__ = ["ai_service", "AIService"]
