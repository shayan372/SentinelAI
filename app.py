import os
import re
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
    try:
        client = OpenAI(
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
    except Exception:
        client = None


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
# LLM FUNCTION
# ============================================================

def ask_llm(system_prompt, user_prompt, fallback_text, max_tokens=3000):

    if client is not None:

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

        except Exception:
            pass

    # Evidence-based fallback
    return fallback_text


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

    source_ips = (
        logs["Source IP"]
        .dropna()
        .unique()
        .tolist()
    )

    usernames = (
        logs["Username"]
        .dropna()
        .unique()
        .tolist()
    )

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
# THREAT ANALYSIS FALLBACK
# ============================================================

def threat_analysis_fallback(investigation):

    failed = investigation["failed_logins"]
    successful = investigation["successful_logins"]
    privilege = investigation["privilege_access_events"]
    unusual = investigation["unusual_activity_events"]

    source_ips = ", ".join(
        investigation["source_ips"]
    )

    return f"""
### Evidence-Based Threat Assessment

**Observed sequence**

1. {failed} failed login attempts were recorded for the
   `admin` account.
2. A successful login was subsequently recorded.
3. The successful login originated from the same observed
   source IP: `{source_ips}`.
4. A privilege-access event followed the successful login.
5. An unusual-activity event was subsequently recorded.

**Assessment**

The observed sequence represents a security-relevant pattern
that warrants investigation and human review.

The logs establish the occurrence of the recorded events, but
they do **not** establish malicious intent or confirm that the
system was compromised.

No additional attacker identity, malware, data theft, or other
activity is inferred beyond the supplied evidence.

**Recommended Human Review**

- Verify whether the successful login was authorized.
- Review the privilege-access event and associated account activity.
- Investigate the unusual-activity event using additional security
  telemetry if available.
- Preserve the supplied logs for further investigation.

**Confidence**

Evidence is sufficient to identify an unusual authentication and
privilege-access sequence, but insufficient to confirm malicious
activity from these logs alone.
""".strip()


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

    fallback = threat_analysis_fallback(
        investigation
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
        "Analyze the supplied incident evidence.",
        fallback,
        max_tokens=2000
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

    timeline = timeline.sort_values(
        "Timestamp"
    )

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
# FINAL REPORT FALLBACK
# ============================================================

def final_report_fallback(
    logs,
    investigation,
    threat_analysis,
    timeline
):

    source_ip = investigation["source_ips"][0]

    timeline_text = "\n".join(
        [
            f"- {event['time']} — "
            f"{event['event']} — "
            f"User: {event['username']} — "
            f"IP: {event['source_ip']}"
            for event in timeline
        ]
    )

    return f"""
# Evidence-First Investigation Report

## Executive Summary

SentinelAI analyzed incident `INC-2026-001` using
{investigation['total_events']} supplied security events.

The observed sequence contains repeated failed login attempts,
a subsequent successful login, privilege access, and unusual
activity involving the same observed source IP.

This sequence warrants human security review.

## Observed Evidence

- Failed login attempts: **{investigation['failed_logins']}**
- Successful login events: **{investigation['successful_logins']}**
- Privilege access events: **{investigation['privilege_access_events']}**
- Unusual activity events: **{investigation['unusual_activity_events']}**
- Observed username: **admin**
- Observed source IP: **{source_ip}**

## Timeline

{timeline_text}

## Threat Assessment

The supplied evidence shows a sequence of authentication,
successful access, privilege access, and unusual activity.

The sequence is security-relevant and should be investigated.

However, the supplied logs alone do **not** confirm malicious
intent or confirmed system compromise.

SentinelAI does not infer additional activity that is not present
in the supplied evidence.

## Uncertainty and Limitations

The dataset contains only six simulated events.

Additional telemetry such as endpoint activity, authentication
details, network records, and system audit logs would be required
for a more complete investigation.

## Recommended Human Review

1. Verify whether the successful `admin` login was authorized.
2. Review the privilege-access event.
3. Investigate the unusual-activity event.
4. Correlate these events with additional available security logs.
5. Preserve the evidence before taking further action.

## Evidence Integrity

The report is based only on the supplied SentinelAI incident
dataset.

No automatic containment or destructive action was performed.
""".strip()


# ============================================================
# ORCHESTRATOR AGENT
# ============================================================

def orchestrate_incident(logs):

    investigation = investigate_logs(
        logs
    )

    threat_analysis = analyze_incident(
        investigation
    )

    timeline = analyze_timeline(
        logs
    )

    specialist_outputs = {
        "Log Investigation Agent": investigation,
        "Threat Analysis Agent": threat_analysis,
        "Timeline Agent": timeline
    }

    validation = evidence_validator(
        logs,
        specialist_outputs
    )

    fallback_report = final_report_fallback(
        logs,
        investigation,
        threat_analysis,
        timeline
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
Evidence Integrity
"""

    final_report = ask_llm(
        report_prompt,
        "Produce the final evidence-first investigation report.",
        fallback_report,
        max_tokens=3000
    )

    final_report = evidence_guard(
        final_report
    )

    return {
        "investigation": investigation,
        "threat_analysis": threat_analysis,
        "timeline": timeline,
        "validation": validation,
        "final_report": final_report
    }


# ============================================================
# ASSISTANT FALLBACK
# ============================================================

def assistant_fallback(question, sentinel_result):

    investigation = sentinel_result[
        "investigation"
    ]

    question_lower = question.lower()

    if (
        "failed" in question_lower
        or "login" in question_lower
    ):

        return (
            f"The evidence records "
            f"{investigation['failed_logins']} failed login "
            f"attempts against the admin account, followed by "
            f"a successful login from the same observed source IP."
        )

    if (
        "privilege" in question_lower
        or "access" in question_lower
    ):

        return (
            "The evidence records one PRIVILEGE_ACCESS event "
            "at 2026-10-10 08:43:17 following the successful "
            "login at 08:42:03."
        )

    if (
        "timeline" in question_lower
        or "happened" in question_lower
    ):

        return (
            "The observed sequence was: three failed logins, "
            "one successful login, one privilege-access event, "
            "and one unusual-activity event. All six events "
            "involve the admin account and the same observed IP."
        )

    if (
        "attack" in question_lower
        or "compromise" in question_lower
        or "malicious" in question_lower
    ):

        return (
            "The logs show a security-relevant sequence, but "
            "they do not establish malicious intent or confirm "
            "system compromise. Human review and additional "
            "telemetry are required."
        )

    return (
        "Based on the supplied evidence, SentinelAI identified "
        "three failed logins, one successful login, one "
        "privilege-access event, and one unusual-activity event. "
        "The evidence warrants human review but does not by "
        "itself confirm malicious intent or compromise."
    )


# ============================================================
# SENTINEL ASSISTANT
# ============================================================

def sentinel_assistant(
    question,
    sentinel_result
):

    context = {
        "investigation": sentinel_result[
            "investigation"
        ],
        "threat_analysis": sentinel_result[
            "threat_analysis"
        ],
        "timeline": sentinel_result[
            "timeline"
        ],
        "final_report": sentinel_result[
            "final_report"
        ]
    }

    fallback = assistant_fallback(
        question,
        sentinel_result
    )

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
        fallback,
        max_tokens=1200
    )

    return evidence_guard(
        answer
    )


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ SentinelAI")

st.markdown(
    """
### AI Incident Response & Evidence-First Investigation

SentinelAI uses specialized AI agents to investigate security
incidents, analyze threats, reconstruct timelines, and produce
an evidence-first investigation report.
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

        st.session_state[
            "sentinel_result"
        ] = result


# ============================================================
# DISPLAY RESULTS
# ============================================================

if "sentinel_result" in st.session_state:

    result = st.session_state[
        "sentinel_result"
    ]

    investigation = result[
        "investigation"
    ]

    threat_analysis = result[
        "threat_analysis"
    ]

    timeline = result[
        "timeline"
    ]


    # ========================================================
    # SPECIALIST AGENTS
    # ========================================================

    st.header(
        "🤖 Specialist Agent Outputs"
    )


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

        for observation in (
            threat_analysis["observations"]
        ):

            st.write(
                f"• {observation}"
            )

        st.markdown(
            "### AI Threat Analysis"
        )

        st.markdown(
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


    # ========================================================
    # VALIDATION
    # ========================================================

    st.header(
        "🛡️ Evidence Validation"
    )

    for validation_item in (
        result["validation"]
    ):

        if "passed" in validation_item.lower():

            st.success(
                validation_item
            )

        else:

            st.warning(
                validation_item
            )


    # ========================================================
    # FINAL REPORT
    # ========================================================

    st.header(
        "📄 Final Evidence-First Investigation Report"
    )

    st.markdown(
        result["final_report"]
    )


    # ========================================================
    # HUMAN REVIEW
    # ========================================================

    st.warning(
        "⚠️ Human review is required before taking any "
        "security action. SentinelAI does not automatically "
        "block accounts, isolate systems, or modify infrastructure."
    )


    # ========================================================
    # ASSISTANT
    # ========================================================

    st.header(
        "💬 SentinelAI Assistant"
    )

    st.caption(
        "Ask questions about the current investigation."
    )

    question = st.text_input(
        "Your question",
        placeholder=(
            "Example: What happened before the "
            "privilege access event?"
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

            st.markdown(
                "### Assistant Response"
            )

            st.write(
                answer
            )

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
