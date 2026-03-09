from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from ai_threat_hunter.config import RAW_LOG_FILE, NORMALIZED_LOG_FILE, ALERTS_FILE
from ai_threat_hunter.generator import save_dataset
from ai_threat_hunter.normalizer import normalize_logs
from ai_threat_hunter.hunter import load_hunts, search_hunts, run_hunting_pipeline
from ai_threat_hunter.utils.io import safe_read_csv

st.set_page_config(page_title="AI Threat Hunter", layout="wide")
st.title("AI Threat Hunter")
st.caption("AI-assisted threat hunting lab for simulated endpoint and authentication telemetry")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("1. Generate Logs"):
        df_raw = save_dataset()
        st.success(f"Generated {len(df_raw)} raw events.")

with col2:
    if st.button("2. Normalize Logs"):
        df_norm = normalize_logs()
        st.success(f"Normalized {len(df_norm)} events.")

with col3:
    if st.button("3. Run Hunt Pipeline"):
        df_norm = safe_read_csv(NORMALIZED_LOG_FILE)
        if df_norm.empty:
            st.error("No normalized logs found. Generate and normalize first.")
        else:
            alerts, summary = run_hunting_pipeline(df_norm)
            st.success(f"Hunt pipeline completed. Alerts: {len(alerts)}")
            st.session_state["summary"] = summary

st.divider()

query = st.text_input(
    "Natural-language hunt query",
    placeholder="Example: find powershell abuse and password spray"
)

hunts = load_hunts()
matched_hunts = search_hunts(query, hunts) if query else []

if query:
    st.subheader("Matched Hunt Prompts")
    if matched_hunts:
        for hunt in matched_hunts:
            st.markdown(f"**{hunt['name']}** — {hunt['description']}")
    else:
        st.info("No hunt prompts matched your query.")

raw_df = safe_read_csv(RAW_LOG_FILE)
norm_df = safe_read_csv(NORMALIZED_LOG_FILE)
alerts_df = safe_read_csv(ALERTS_FILE)

st.divider()
st.subheader("Investigation Filters")

if not alerts_df.empty:

    severity_options = ["All"] + sorted(alerts_df["severity"].dropna().unique().tolist())
    selected_severity = st.selectbox("Filter by Severity", severity_options)

    host_options = ["All"] + sorted(alerts_df["host"].dropna().unique().tolist())
    selected_host = st.selectbox("Filter by Host", host_options)

    if selected_severity != "All":
        alerts_df = alerts_df[alerts_df["severity"] == selected_severity]

    if selected_host != "All":
        alerts_df = alerts_df[alerts_df["host"] == selected_host]

left, right = st.columns([2, 1])

with left:
    st.subheader("Alerts")
    if alerts_df.empty:
        st.info("No alerts yet. Run the pipeline.")
    else:
        preferred_columns = [
            "timestamp",
            "rule_name",
            "severity",
            "confidence",
            "mitre_tactic",
            "mitre_technique",
            "host",
            "source_ip",
            "user",
            "reason",
        ]

        display_columns = [col for col in preferred_columns if col in alerts_df.columns]

        st.dataframe(alerts_df[display_columns], use_container_width=True)

        st.subheader("Alert Investigation")

        selected_alert = st.selectbox(
            "Select Alert to Investigate",
            alerts_df.index
        )

        alert_details = alerts_df.loc[selected_alert]

        st.json(alert_details.to_dict())

        st.subheader("Host Event Timeline")

        selected_host_value = alert_details.get("host", "")

        if selected_host_value and selected_host_value != "multiple":
            host_events = norm_df[norm_df["host"] == selected_host_value].copy()

            if not host_events.empty:
                if "timestamp" in host_events.columns:
                    host_events["timestamp"] = pd.to_datetime(host_events["timestamp"], errors="coerce")
                    host_events = host_events.sort_values("timestamp", ascending=False)

                timeline_columns = [
                    "timestamp",
                    "event_type",
                    "host",
                    "user",
                    "process_name",
                    "parent_process",
                    "command_line",
                    "source_ip",
                    "status",
                ]

                available_timeline_columns = [
                    col for col in timeline_columns if col in host_events.columns
                ]

                st.dataframe(
                    host_events[available_timeline_columns].head(25),
                    use_container_width=True
                )
            else:
                st.info("No timeline events found for the selected host.")
        else:
            st.info("Timeline unavailable for aggregated alerts like password spray.")

with right:
    st.subheader("AI Analyst Summary")
    summary = st.session_state.get("summary")
    if summary:
        st.write(summary)
    else:
        st.info("Run the hunt pipeline to generate a summary.")

st.divider()

st.subheader("Raw Events")
if raw_df.empty:
    st.info("No raw events generated yet.")
else:
    st.dataframe(raw_df.head(50), use_container_width=True)

st.subheader("Normalized Events")
if norm_df.empty:
    st.info("No normalized events available yet.")
else:
    st.dataframe(norm_df.head(50), use_container_width=True)