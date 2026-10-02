# SentinelAI — AI Incident Response

SentinelAI is an AI-powered defensive cybersecurity investigation system that analyzes security logs through a multi-agent workflow, validates generated findings against authoritative evidence, and provides an analyst assistant for human review.

## Architecture

Security Logs  
↓  
Log Investigation Agent  
↓  
Threat Analysis Agent  
↓  
Timeline Agent  
↓  
Evidence Validator  
↓  
Orchestrator Agent  
↓  
Unified Incident Report  
↓  
Analyst Assistant  
↓  
Human Review

## Core Features

- Multi-agent security investigation
- Security log analysis
- Threat analysis
- Deterministic timeline reconstruction
- Evidence-first validation
- Unsupported-claim detection
- Unified incident reporting
- Analyst Assistant
- Human-in-the-loop review
- Defensive cybersecurity design

## Technology Stack

- Python
- Streamlit
- Pandas
- OpenAI-compatible API
- Groq LLM
- Google Colab
- GitHub

## Evidence-First Design

Raw security logs are treated as the authoritative evidence source.

SentinelAI does not automatically establish:

- Account compromise
- Malicious intent
- Attacker identity
- Malware infection
- Data exfiltration
- Lateral movement
- Persistence

When evidence is insufficient, the system explicitly states that the conclusion is not established by the available evidence.

## Human-in-the-Loop

SentinelAI supports investigation but does not automatically perform security response actions.

Operational decisions remain with a human analyst.

## Demonstration

The current simulated dataset contains:

- 3 LOGIN_FAILED events
- 1 LOGIN_SUCCESS event
- 1 PRIVILEGE_ACCESS event
- 1 UNUSUAL_ACTIVITY event

Example Analyst Assistant question:

> Was the admin account definitely compromised?

Expected evidence-based response:

> That is not established by the available evidence.

## Running

```bash
pip install -r requirements.txt
streamlit run app.py
