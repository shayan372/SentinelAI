
import os
import re
import pandas as pd
import streamlit as st
from openai import OpenAI

st.set_page_config(
    page_title="SentinelAI — AI Incident Response",
    page_icon="🛡️",
    layout="wide"
)

try:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except Exception:
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

MODEL = "llama-3.3-70b-versatile"

client = None

if GROQ_API_KEY:
    try:
        client = OpenAI(
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
   client = None

if GROQ_API_KEY:
    try:
        client = OpenAI(
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
    except Exception:
        client = None
            messages=[
            
        return (
            "AI connection is unavailable.\n\n"
            "The deterministic SentinelAI evidence engine remains active."
        )

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            temperature=0.1,
            max_tokens=max_tokens
        )

        content = response.choices[0].message.content

        if content:
            content = str(content).strip()

        if content:
            return content

        return (
            "The AI model returned an empty response.\n\n"
            "The deterministic evidence engine remains available."
        )

    except Exception as e:
        return (
            "AI analysis could not be completed for this step.\n\n"
            f"Technical status: {str(e)[:300]}\n\n"
            "The deterministic evidence engine remains active."
        )


def investigate_logs(logs):

    system_prompt = """
You are SentinelAI's Log Investigation Agent.

Analyze ONLY the supplied security logs.

STRICT EVIDENCE RULES:
- Use only facts explicitly present in the logs.
- Never invent events, actions, users, IPs, or outcomes.
- Never use the phrases "privilege escalation" or "data exfiltration".
- Never use "attacker", "compromise", "malware",
  "lateral movement", "persistence", or "unauthorized access"
  as established facts.
- PRIVILEGE_ACCESS must remain exactly "PRIVILEGE_ACCESS".
- LOGIN_SUCCESS does not prove account compromise.
- LOGIN_FAILED does not prove brute force.
- UNUSUAL_ACTIVITY does not prove malicious activity.
- If something cannot be established, say:
  "Not established by the available evidence."

Use EXACTLY this format:

## INCIDENT SUMMARY
2-3 concise sentences based only on the logs.

## OBSERVED EVIDENCE
- Maximum 5 factual bullets.
- Preserve exact event names, timestamps, username, and source IP.

## SUSPICIOUS PATTERNS
- Maximum 4 bullets.
- Describe patterns without assigning attacker intent.
- Do not name an attack type unless explicitly established.

## RISK ASSESSMENT
Risk Level: LOW / MEDIUM / HIGH / CRITICAL
Reason: 1-2 sentences based only on observed evidence.

## EVIDENCE LIMITATIONS
- Maximum 4 bullets.
- State what the supplied logs cannot establish.

## HUMAN REVIEW
- Maximum 3 investigation steps.
- Recommendations must be for human review only.

Be concise and professional.
"""

    user_prompt = f"""
Analyze these security logs:

{logs}

Return only the requested SentinelAI report.
"""

    response = ask_llm(
        system_prompt,
        user_prompt,
        max_tokens=650
    )

    forbidden_replacements = {
        "privilege escalation": "privilege-access activity",
        "Privilege Escalation": "privilege-access activity",
        "data exfiltration": "data transfer not established",
        "Data Exfiltration": "data transfer not established",
        "attacker activity": "activity of unknown origin",
        "Attacker activity": "activity of unknown origin"
    }

    for incorrect, corrected in forbidden_replacements.items():
        response = response.replace(
            incorrect,
            corrected
        )

    return response


def analyze_incident(investigation):

    system_prompt = """
You are SentinelAI's Threat Analysis Agent.

Analyze ONLY the supplied investigation.

CRITICAL RULES:
- Use exact evidence from the investigation.
- LOGIN_FAILED does not prove brute force.
- LOGIN_SUCCESS does not prove compromise.
- PRIVILEGE_ACCESS must remain exactly "PRIVILEGE_ACCESS".
- Do not call it privilege escalation.
- Do not claim unauthorized access.
- Do not introduce data exfiltration, malware, attacker activity,
  or system damage.
- If evidence is insufficient, explicitly say so.
- Hypotheses must be clearly labeled UNCONFIRMED.

Use EXACTLY this format:

## INCIDENT TYPE
Suspicious authentication and system activity;
specific attack type not established.

## OBSERVED INDICATORS
- Maximum 4 factual bullets.

## HYPOTHESES
- Maximum 3 clearly labeled UNCONFIRMED hypotheses.
- Keep them general and evidence-aware.

## RISK ASSESSMENT
Risk Level: LOW / MEDIUM / HIGH / CRITICAL
Reason: Explain why the activity requires attention
without claiming compromise.

## EVIDENCE LIMITATIONS
- Maximum 4 bullets.

## HUMAN REVIEW
- Maximum 3 human-review actions.

Be concise.
"""

    user_prompt = f"""
Analyze this SentinelAI investigation:

{investigation}

Return only the requested report.
"""

    return ask_llm(
        system_prompt,
        user_prompt,
        max_tokens=700
    )


def analyze_timeline(logs):

    timeline = logs.copy()

    timeline["Timestamp"] = pd.to_datetime(
        timeline["Timestamp"]
    )

    timeline = timeline.sort_values(
        "Timestamp"
    ).reset_index(drop=True)

    timeline["GapSeconds"] = (
        timeline["Timestamp"].diff().dt.total_seconds()
    )

    observations = []

    for i, row in timeline.iterrows():

        timestamp = row["Timestamp"].strftime("%H:%M:%S")
        event = row["Event Type"]
        username = row["Username"]
        ip = row["Source IP"]

        if i == 0:
            observations.append(
                f"- {timestamp}: {event} for {username} from {ip}."
            )
        else:
            gap = int(row["GapSeconds"])

            observations.append(
                f"- {timestamp}: {event} for {username} from {ip} "
                f"({gap}s after previous event)."
            )

    gaps = []

    for i in range(1, len(timeline)):

        previous_event = timeline.loc[
            i - 1, "Event Type"
        ]

        current_event = timeline.loc[
            i, "Event Type"
        ]

        gap = int(
            (
                timeline.loc[i, "Timestamp"]
                - timeline.loc[i - 1, "Timestamp"]
            ).total_seconds()
        )

        gaps.append(
            f"- {gap}s between {previous_event} and {current_event}."
        )

    total_seconds = int(
        (
            timeline.iloc[-1]["Timestamp"]
            - timeline.iloc[0]["Timestamp"]
        ).total_seconds()
    )

    minutes = total_seconds // 60
    seconds = total_seconds % 60

    duration = (
        f"{minutes}m {seconds}s"
        if minutes > 0
        else f"{seconds}s"
    )

    first_time = timeline.iloc[0]["Timestamp"].strftime(
        "%H:%M:%S"
    )

    last_time = timeline.iloc[-1]["Timestamp"].strftime(
        "%H:%M:%S"
    )

    return f"""
## TIMELINE SUMMARY

Investigation window: {first_time} to {last_time}.

Total duration: {duration}.

## CHRONOLOGICAL OBSERVATIONS

{chr(10).join(observations)}

## TIME GAPS

{chr(10).join(gaps)}

## TIMELINE LIMITATIONS

- Only the supplied events are represented.
- The logs do not provide session identifiers or detailed user actions.
- Timing alone does not establish compromise or malicious intent.
""".strip()


def evidence_guard(response):

    replacements = {
        "internal IP": "source IP",
        "Internal IP": "source IP",
        "internal network": "network context not established",
        "Internal network": "network context not established",
        "gained elevated rights": "had a privilege-access event",
        "gained elevated privileges": "had a privilege-access event",
        "Privilege elevation": "Privilege-access event",
        "privilege elevation": "privilege-access event",
        "privilege escalation": "privilege-access event",
        "Privilege escalation": "privilege-access event",
        "subsequent privilege elevation": "subsequent privilege-access event"
    }

    guarded_response = str(response)

    for incorrect, corrected in replacements.items():
        guarded_response = guarded_response.replace(
            incorrect,
            corrected
        )

    return guarded_response


def evidence_validator(logs, agent_outputs):

    valid_times = set(
        pd.to_datetime(logs["Timestamp"])
        .dt.strftime("%H:%M:%S")
        .tolist()
    )

    valid_ips = set(
        logs["Source IP"].astype(str)
    )

    valid_users = set(
        logs["Username"].astype(str).str.lower()
    )

    valid_events = set(
        logs["Event Type"].astype(str)
    )

    results = {}
    issues = []

    for agent_name, output in agent_outputs.items():

        output = str(output)

        agent_result = {
            "unsupported_timestamps": [],
            "unsupported_ips": [],
            "unsupported_users": [],
            "unsupported_events": [],
            "unsupported_claims": []
        }

        # Timestamp validation
        found_times = set(
            re.findall(
                r"\b\d{2}:\d{2}:\d{2}\b",
                output
            )
        )

        for timestamp in found_times:

            if timestamp not in valid_times:

                agent_result["unsupported_timestamps"].append(
                    timestamp
                )

                issues.append(
                    f"{agent_name}: unsupported timestamp {timestamp}"
                )

        # IP validation
        found_ips = set(
            re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                output
            )
        )

        for ip in found_ips:

            if ip not in valid_ips:

                agent_result["unsupported_ips"].append(ip)

                issues.append(
                    f"{agent_name}: unsupported IP {ip}"
                )

        # Username validation
        found_users = set()

        username_patterns = [
            r"\busername\s*[:=]\s*([A-Za-z0-9_.-]+)",
            r"\buser\s*[:=]\s*([A-Za-z0-9_.-]+)",
            r"\baccount\s*[:=]\s*([A-Za-z0-9_.-]+)"
        ]

        for pattern in username_patterns:

            matches = re.findall(
                pattern,
                output,
                flags=re.IGNORECASE
            )

            for username in matches:

                username = username.lower()

                if username in valid_users:
                    continue

                found_users.add(username)

        for username in found_users:

            agent_result["unsupported_users"].append(
                username
            )

            issues.append(
                f"{agent_name}: unsupported username {username}"
            )

        # Event validation
        event_pattern = r"\b[A-Z][A-Z0-9_]{3,}\b"

        found_events = set(
            re.findall(
                event_pattern,
                output
            )
        )

        ignored_tokens = {
            "AI",
            "IP",
            "LLM",
            "HIGH",
            "MEDIUM",
            "LOW",
            "CRITICAL",
            "UNCONFIRMED",
            "PASS",
            "FAIL",
            "WARNING",
            "SENTINELAI",
            "INCIDENT",
            "SUMMARY",
            "OBSERVED",
            "EVIDENCE",
            "RISK",
            "LEVEL",
            "HUMAN",
            "REVIEW",
            "ACCESS",
            "TYPE",
            "NOTE"
        }

        for event in found_events:

            if event in ignored_tokens:
                continue

            if event in valid_events:
                continue

            security_keywords = [
                "LOGIN",
                "ACCESS",
                "ACTIVITY",
                "PRIVILEGE",
                "AUTH",
                "SESSION",
                "FILE",
                "NETWORK"
            ]

            if any(
                keyword in event
                for keyword in security_keywords
            ):

                agent_result["unsupported_events"].append(
                    event
                )

                issues.append(
                    f"{agent_name}: unsupported event {event}"
                )

        # Unsupported claim detection
        forbidden_claims = [
            "privilege escalation",
            "privilege escalated",
            "gained elevated privileges",
            "elevated privileges were obtained",
            "account compromised",
            "account was compromised",
            "successful brute force",
            "successful brute-force",
            "data exfiltration",
            "malware infection",
            "attacker activity",
            "attacker accessed",
            "attacker gained access",
            "lateral movement",
            "persistence"
        ]

        # Ignore limitation sections because they may
        # mention these terms as things NOT established.
        claim_text = output

        limitation_markers = [
            "## EVIDENCE LIMITATIONS",
            "## TIMELINE LIMITATIONS",
            "EVIDENCE LIMITATIONS:",
            "TIMELINE LIMITATIONS:"
        ]

        for marker in limitation_markers:

            if marker.lower() in claim_text.lower():

                parts = re.split(
                    re.escape(marker),
                    claim_text,
                    flags=re.IGNORECASE
                )

                claim_text = parts[0]

        lowered = claim_text.lower()

        for claim in forbidden_claims:

            if claim in lowered:

                agent_result["unsupported_claims"].append(
                    claim
                )

                issues.append(
                    f"{agent_name}: unsupported claim '{claim}'"
                )

        results[agent_name] = agent_result

    status = (
        "⚠ REVIEW REQUIRED"
        if issues
        else "✅ VALIDATED"
    )

    return {
        "status": status,
        "agent_results": results,
        "issues": issues
    }


def orchestrate_incident(logs):

    # Agent 1
    investigation = investigate_logs(logs)

    # Agent 2
    incident_analysis = analyze_incident(
        investigation
    )

    # Agent 3
    timeline = analyze_timeline(logs)

    # Raw logs are authoritative
    evidence_table = logs.to_string(
        index=False
    )

    system_prompt = """
You are SentinelAI's Final Orchestrator.

Create a professional defensive cybersecurity
incident report.

CRITICAL EVIDENCE RULES:

- RAW SECURITY LOGS are the authoritative evidence.
- Never invent facts or events.
- Never call PRIVILEGE_ACCESS "privilege escalation".
- Never claim account compromise.
- Never claim malicious intent.
- Never claim malware.
- Never claim data exfiltration.
- Never claim lateral movement.
- Never claim persistence.
- Never identify an attacker.
- LOGIN_SUCCESS does not prove compromise.
- UNUSUAL_ACTIVITY does not prove malicious activity.
- If something cannot be established, write:
  "Not established by the available evidence."

Agent analyses are interpretations only.
They cannot override the raw logs.

Return:

SENTINELAI INCIDENT REPORT

1. Executive Summary

2. Key Evidence

3. Security Assessment

4. Risk Level

5. Evidence Limitations

6. Recommended Human Review

Keep it concise and evidence-based.
"""

    user_prompt = f"""
RAW SECURITY LOGS — AUTHORITATIVE:

{evidence_table}

LOG INVESTIGATION AGENT:

{investigation}

THREAT ANALYSIS AGENT:

{incident_analysis}

TIMELINE AGENT:

{timeline}

Generate the final SentinelAI incident report.
"""

    final_report = ask_llm(
        system_prompt,
        user_prompt,
        max_tokens=900
    )

    final_report = evidence_guard(
        final_report
    )

    return {
        "investigation": investigation,
        "incident_analysis": incident_analysis,
        "timeline": timeline,
        "final_report": final_report
    }


def sentinel_assistant(question, sentinel_result):

    system_prompt = """
You are SentinelAI Assistant, a defensive cybersecurity assistant.

Use ONLY information contained in the supplied SentinelAI results.

Rules:
- Do not invent events, IPs, users, or outcomes.
- Do not claim account compromise unless explicitly confirmed.
- Do not claim malicious intent unless explicitly confirmed.
- Do not call PRIVILEGE_ACCESS "privilege escalation".
- Do not claim malware, data theft, lateral movement, or persistence
  unless explicitly supported.
- Clearly distinguish facts from assessments.
- If something cannot be determined, say:
  "That is not established by the available evidence."
- Recommendations are for human review only.
- Never claim SentinelAI performed an operational security action.

Answer directly and professionally.
"""

    user_prompt = f"""
SENTINELAI INVESTIGATION:

{sentinel_result["investigation"]}

SENTINELAI INCIDENT ANALYSIS:

{sentinel_result["incident_analysis"]}

SENTINELAI FINAL REPORT:

{sentinel_result["final_report"]}

USER QUESTION:

{question}
"""

    response = ask_llm(
        system_prompt,
        user_prompt
    )

    return evidence_guard(response)



security_logs = pd.DataFrame([
    {"Timestamp": "2026-10-10 08:41:12", "Event Type": "LOGIN_FAILED", "Username": "admin", "Source IP": "185.71.22.14"},
    {"Timestamp": "2026-10-10 08:41:18", "Event Type": "LOGIN_FAILED", "Username": "admin", "Source IP": "185.71.22.14"},
    {"Timestamp": "2026-10-10 08:41:25", "Event Type": "LOGIN_FAILED", "Username": "admin", "Source IP": "185.71.22.14"},
    {"Timestamp": "2026-10-10 08:42:03", "Event Type": "LOGIN_SUCCESS", "Username": "admin", "Source IP": "185.71.22.14"},
    {"Timestamp": "2026-10-10 08:43:17", "Event Type": "PRIVILEGE_ACCESS", "Username": "admin", "Source IP": "185.71.22.14"},
    {"Timestamp": "2026-10-10 08:45:31", "Event Type": "UNUSUAL_ACTIVITY", "Username": "admin", "Source IP": "185.71.22.14"}
])

st.title("🛡️ SentinelAI")
st.caption("AI Incident Response • Multi-Agent Security Analysis • Evidence-First Reasoning")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.metric("Incident", "INC-2026-001")

with c2:
    st.metric("Events", len(security_logs))

with c3:
    st.metric("Agents", "5")

with c4:
    st.metric("Mode", "Simulated")

st.divider()

st.subheader("🔐 Security Events")
st.dataframe(
    security_logs,
    use_container_width=True,
    hide_index=True
)

if "sentinel_result" not in st.session_state:
    st.session_state.sentinel_result = None

if "validation_result" not in st.session_state:
    st.session_state.validation_result = None

if st.button(
    "🚀 Run SentinelAI Investigation",
    type="primary",
    use_container_width=True
):

    with st.spinner("Running multi-agent investigation..."):

        result = orchestrate_incident(security_logs)

        validation = evidence_validator(
            security_logs,
            {
                "Log Investigation Agent": result["investigation"],
                "Threat Analysis Agent": result["incident_analysis"],
                "Timeline Agent": result["timeline"]
            }
        )

        st.session_state.sentinel_result = result
        st.session_state.validation_result = validation

    st.success("SentinelAI investigation completed.")

result = st.session_state.sentinel_result
validation = st.session_state.validation_result

if result:

    st.divider()
    st.subheader("🧩 Multi-Agent Investigation")

    a, b, c = st.columns(3)

    with a:
        st.success("🔍 Log Investigation\n\nCompleted")

    with b:
        st.success("🎯 Threat Analysis\n\nCompleted")

    with c:
        st.success("🕒 Timeline Analysis\n\nCompleted")

    st.subheader("🛡️ Evidence Validation")

    if validation and validation["status"] == "✅ VALIDATED":
        st.success(
            "✅ Evidence validation passed — "
            "no unsupported evidence detected."
        )
    else:
        st.warning(
            validation["status"]
            if validation
            else "Validation unavailable."
        )

    tabs = st.tabs([
        "🔍 Investigation",
        "🎯 Threat Analysis",
        "🕒 Timeline",
        "🧩 Final Report"
    ])

    with tabs[0]:
        st.markdown(result["investigation"])

    with tabs[1]:
        st.markdown(result["incident_analysis"])

    with tabs[2]:
        st.markdown(result["timeline"])

    with tabs[3]:
        st.markdown(result["final_report"])

    st.divider()
    st.subheader("🤖 SentinelAI Analyst Assistant")

    question = st.text_input(
        "Analyst question",
        placeholder="Was the admin account definitely compromised?"
    )

    if st.button("Ask SentinelAI", use_container_width=True):

        if question.strip():

            with st.spinner("Analyzing investigation results..."):

                answer = sentinel_assistant(
                    question,
                    result
                )

            st.info(answer)

        else:
            st.warning("Please enter a question.")

    st.divider()
    st.subheader("👤 Human Review")

    st.warning(
        "Pending human review — SentinelAI does not automatically "
        "perform security response actions."
    )

    st.checkbox(
        "I have reviewed the evidence and investigation report."
    )

    st.caption(
        "SentinelAI is a defensive cybersecurity research and "
        "demonstration system using simulated security logs."
    )
