import os
import re
import requests
import pandas as pd
import streamlit as st
from openai import OpenAI


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SentinelAI — AI Incident Response",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# GROQ CONFIGURATION
# ============================================================

try:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
except Exception:
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

MODEL = "openai/gpt-oss-20b"

client = None

if GROQ_API_KEY:
    client = OpenAI(
        api_key=GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1"
    )


# Temporary diagnostics
st.write("GROQ CLIENT CREATED:", client is not None)
st.write(
    "KEY SUFFIX:",
    GROQ_API_KEY[-4:] if GROQ_API_KEY else "NONE"
)


# ============================================================
# DIRECT GROQ CONNECTION TEST
# ============================================================

try:
    test_response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": "Reply with OK"
                }
            ],
            "max_tokens": 100
        },
        timeout=30
    )

    st.write("DIRECT GROQ STATUS:", test_response.status_code)
    st.write(
        "DIRECT GROQ RESPONSE:",
        test_response.text[:500]
    )

except Exception as e:
    st.write("DIRECT GROQ ERROR:", str(e))


# ============================================================
# LLM FUNCTION
# ============================================================

def ask_llm(system_prompt, user_prompt, max_tokens=3000):

    if client is None:
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


# ============================================================
# SECURITY LOG DATA
# ============================================================

security_logs = pd.DataFrame([
    {
        "Timestamp": "2026-10-10 08:41:12",
        "Event Type": "LOGIN_FAILED",
        "Username": "admin",
        "Source IP": "185.71.22.14"
    },
    {
        "Timestamp": "2026-10-10 08:41:18",
        "Event Type": "LOGIN_FAILED",
        "Username": "admin",
        "Source IP": "185.71.22.14"
    },
    {
        "Timestamp": "2026-10-10 08:41:25",
        "Event Type": "LOGIN_FAILED",
        "Username": "admin",
        "Source IP": "185.71.22.14"
    },
    {
        "Timestamp": "2026-10-10 08:42:03",
        "Event Type": "LOGIN_SUCCESS",
        "Username": "admin",
        "Source IP": "185.71.22.14"
    },
    {
        "Timestamp": "2026-10-10 08:43:17",
        "Event Type": "PRIVILEGE_ACCESS",
        "Username": "admin",
        "Source IP": "185.71.22.14"
    },
    {
        "Timestamp": "2026-10-10 08:45:31",
        "Event Type": "UNUSUAL_ACTIVITY",
        "Username": "admin",
        "Source IP": "185.71.22.14"
    }
])


# ============================================================
# LOG INVESTIGATION AGENT
# ============================================================

def investigate_logs(logs):

    events = logs.to_dict("records")

    failed_logins = logs[
        logs["Event Type"] == "LOGIN_FAILED"
    ]

    successful_logins = logs[
        logs["Event Type"] == "LOGIN_SUCCESS"
    ]

    privilege_events = logs[
        logs["Event Type"] == "PRIVILEGE_ACCESS"
    ]

    unusual_events = logs[
        logs["Event Type"] == "UNUSUAL_ACTIVITY"
    ]

    source_ips = logs["Source IP"].dropna().unique().tolist()

    usernames = logs["Username"].dropna().unique().tolist()

    result = {
        "incident_id": "INC-2026-001",
        "total_events": len(logs),
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "privilege_access_events": len(privilege_events),
        "unusual_activity_events": len(unusual_events),
        "source_ips": source_ips,
        "usernames": usernames,
        "events": events
    }

    return result


# ============================================================
# THREAT ANALYSIS AGENT
# ============================================================

def analyze_incident(investigation):

    failed = investigation["failed_logins"]
    successful = investigation["successful_logins"]
    privilege = investigation["privilege_access_events"]
    unusual = investigation["unusual_activity_events"]

    observations = []

    if failed > 0:
        observations.append(
            f"{failed} failed login attempt(s) were recorded."
        )

    if successful > 0:
        observations.append(
            f"{successful} successful login event(s) were recorded."
        )

    if privilege > 0:
        observations.append(
            f"{privilege} privilege access event(s) were recorded."
        )

    if unusual > 0:
        observations.append(
            f"{unusual} unusual activity event(s) were recorded."
        )

    threat_prompt = f"""
You are the Threat Analysis Agent in SentinelAI.

Analyze only the supplied evidence.

Incident:
{investigation}

Requirements:
- Do not invent events.
- Do not invent indicators.
- Do not claim confirmed compromise.
- Clearly distinguish facts from interpretations.
- State that malicious intent cannot be confirmed from these logs alone.
- Provide concise security analysis.
"""

    ai_analysis = ask_llm(
        threat_prompt,
        "Analyze the supplied incident evidence."
    )

    return {
        "observations": observations,
        "ai_analysis": ai_analysis
    }


# ============================================================
# TIMELINE AGENT
# ============================================================

def analyze_timeline(logs):

    timeline = logs.copy()

    timeline["Timestamp"] = pd.to_datetime(
        timeline["Timestamp"]
    )

    timeline = timeline.sort_values("Timestamp")

    timeline_events = []

    for _, row in timeline.iterrows():

        timeline_events.append(
            {
                "time": row["Timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "event": row["Event Type"],
                "username": row["Username"],
                "source_ip": row["Source IP"]
            }
        )

    return timeline_events


# ============================================================
# EVIDENCE GUARD
# ============================================================

def evidence_guard(response):

    if not response:
        return response

    forbidden_patterns = [
        r"confirmed attack",
        r"confirmed breach",
        r"attacker\s+is",
        r"the attacker",
        r"malware\s+was\s+installed",
        r"data\s+was\s+stolen"
    ]

    cleaned = response

    for pattern in forbidden_patterns:

        cleaned = re.sub(
            pattern,
            "not confirmed by the supplied evidence",
            cleaned,
            flags=re.IGNORECASE
        )

    return cleaned


# ============================================================
# EVIDENCE VALIDATOR
# ============================================================

def evidence_validator(logs, agent_outputs):

    log_text = logs.to_string(index=False)

    validation_results = []

    for agent_name, output in agent_outputs.items():

        if output is None:
            validation_results.append(
                f"{agent_name}: No output available."
            )
            continue

        output_text = str(output)

        fabricated_terms = [
            "malware installed",
            "data stolen",
            "confirmed breach",
            "confirmed attacker",
            "ransomware deployed"
        ]

        found = []

        for term in fabricated_terms:

            if term.lower() in output_text.lower():
                found.append(term)

        if found:

            validation_results.append(
                f"{agent_name}: Review required — "
                f"unsupported claims detected."
            )

        else:

            validation_results.append(
                f"{agent_name}: Evidence validation passed."
            )

    return validation_results


# ============================================================
# ORCHESTRATOR AGENT
# ============================================================

def orchestrate_incident(logs):

    investigation = investigate_logs(logs)

    threat_analysis = analyze_incident(
        investigation
    )

    timeline = analyze_timeline(logs)

    specialist_outputs = {
        "Log Investigation Agent": investigation,
        "Threat Analysis Agent": threat_analysis,
        "Timeline Agent": timeline
    }

    validation = evidence_validator(
        logs,
        specialist_outputs
    )

    report_prompt = f"""
You are the Orchestrator Agent for SentinelAI.

Create an evidence-first incident investigation report.

Evidence:
{logs.to_dict("records")}

Log Investigation:
{investigation}

Threat Analysis:
{threat_analysis}

Timeline:
{timeline}

Rules:
1. Use only supplied evidence.
2. Do not invent events or indicators.
3. Separate facts from interpretations.
4. Do not claim confirmed malicious intent.
5. Do not claim confirmed compromise.
6. Do not recommend automatic destructive actions.
7. Clearly identify uncertainty.
8. Keep the report professional and concise.

Structure:

Executive Summary
Observed Evidence
Timeline
Threat Assessment
Uncertainty / Limitations
Recommended Human Review
"""

    final_report = ask_llm(
        report_prompt,
        "Produce the final evidence-first investigation report.",
        max_tokens=3000
    )

    final_report = evidence_guard(final_report)

    return {
        "investigation": investigation,
        "threat_analysis": threat_analysis,
        "timeline": timeline,
        "validation": validation,
        "final_report": final_report
    }


# ============================================================
# SENTINEL ASSISTANT
# ============================================================

def sentinel_assistant(question, sentinel_result):

    context = {
        "investigation": sentinel_result["investigation"],
        "threat_analysis": sentinel_result["threat_analysis"],
        "timeline": sentinel_result["timeline"],
        "final_report": sentinel_result["final_report"]
    }

    system_prompt = """
You are SentinelAI Assistant.

Answer questions using only the investigation evidence supplied.

Rules:
- Do not invent facts.
- Do not invent security events.
- Do not claim confirmed compromise.
- Clearly distinguish evidence from interpretation.
- If the evidence does not answer the question, say so.
- Do not perform automatic security actions.
- Keep answers concise and professional.
"""

    answer = ask_llm(
        system_prompt,
        f"""
Investigation context:

{context}

User question:

{question}
""",
        max_tokens=1200
    )

    return evidence_guard(answer)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ SentinelAI")

st.markdown(
    """
### AI Incident Response & Evidence-First Investigation

SentinelAI uses specialized AI agents to investigate security incidents,
analyze threats, reconstruct timelines, and produce an evidence-first
investigation report.
"""
)


# ============================================================
# METRICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Incident",
        "INC-2026-001"
    )

with col2:
    st.metric(
        "Events",
        len(security_logs)
    )

with col3:
    st.metric(
        "Agents",
        "5"
    )

with col4:
    st.metric(
        "Mode",
        "Simulated"
    )


st.divider()


# ============================================================
# INVESTIGATION
# ============================================================

st.header("🔍 Investigation")

st.dataframe(
    security_logs,
    width="stretch",
    hide_index=True
)


# ============================================================
# RUN INVESTIGATION
# ============================================================

if st.button(
    "🚀 Run SentinelAI Investigation",
    type="primary",
    width="stretch"
):

    with st.spinner(
        "SentinelAI agents are investigating the incident..."
    ):

        result = orchestrate_incident(
            security_logs
        )

        st.session_state["sentinel_result"] = result


# ============================================================
# DISPLAY RESULTS
# ============================================================

if "sentinel_result" in st.session_state:

    result = st.session_state["sentinel_result"]

    investigation = result["investigation"]
    threat_analysis = result["threat_analysis"]
    timeline = result["timeline"]


    # --------------------------------------------------------
    # SPECIALIST AGENTS
    # --------------------------------------------------------

    st.header("🤖 Specialist Agent Outputs")


    with st.expander(
        "📋 Log Investigation Agent",
        expanded=True
    ):

        st.write(
            f"**Total Events:** "
            f"{investigation['total_events']}"
        )

        st.write(
            f"**Failed Logins:** "
            f"{investigation['failed_logins']}"
        )

        st.write(
            f"**Successful Logins:** "
            f"{investigation['successful_logins']}"
        )

        st.write(
            f"**Privilege Access Events:** "
            f"{investigation['privilege_access_events']}"
        )

        st.write(
            f"**Unusual Activity Events:** "
            f"{investigation['unusual_activity_events']}"
        )

        st.write(
            f"**Source IPs:** "
            f"{', '.join(investigation['source_ips'])}"
        )


    with st.expander(
        "⚠️ Threat Analysis Agent",
        expanded=True
    ):

        for observation in threat_analysis["observations"]:
            st.write(f"• {observation}")

        st.markdown("### AI Threat Analysis")

        st.write(
            threat_analysis["ai_analysis"]
        )


    with st.expander(
        "🕒 Timeline Agent",
        expanded=True
    ):

        for event in timeline:

            st.write(
                f"**{event['time']}** — "
                f"{event['event']} — "
                f"User: `{event['username']}` — "
                f"IP: `{event['source_ip']}`"
            )


    with st.expander(
        "🧠 Orchestrator Agent",
        expanded=True
    ):

        st.write(
            "The Orchestrator Agent combines the outputs "
            "from the specialist agents and produces the "
            "final evidence-first investigation."
        )


    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    st.header("🛡️ Evidence Validation")

    for validation_item in result["validation"]:

        if "passed" in validation_item.lower():

            st.success(validation_item)

        else:

            st.warning(validation_item)


    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    st.header("📄 Final Evidence-First Investigation Report")

    st.markdown(
        result["final_report"]
    )


    # --------------------------------------------------------
    # HUMAN REVIEW
    # --------------------------------------------------------

    st.warning(
        "⚠️ Human review is required before taking any "
        "security action. SentinelAI does not automatically "
        "block accounts, isolate systems, or modify infrastructure."
    )


    # --------------------------------------------------------
    # ASSISTANT
    # --------------------------------------------------------

    st.header("💬 SentinelAI Assistant")

    st.caption(
        "Ask questions about the current investigation."
    )

    question = st.text_input(
        "Your question",
        placeholder=(
            "Example: What happened before the privilege access event?"
        )
    )

    if st.button(
        "Ask SentinelAI",
        width="stretch"
    ):

        if question.strip():

            with st.spinner(
                "SentinelAI Assistant is analyzing the evidence..."
            ):

                answer = sentinel_assistant(
                    question,
                    result
                )

            st.markdown("### Assistant Response")

            st.write(answer)

        else:

            st.info(
                "Please enter a question first."
            )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "SentinelAI — Evidence-First AI Incident Response | "
    "Simulated Environment"
)
