import streamlit as st
import pandas as pd
from collections import Counter

st.set_page_config(page_title="Intelligent SOC Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ Intelligent SOC Threat Detection System")
st.caption("Educational prototype • Uses sample or user-provided security logs • No real devices are scanned or blocked")

REQUIRED = {"timestamp", "source_ip", "username", "event_type", "status"}

def analyze_logs(df):
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))

    df["event_type"] = df["event_type"].astype(str).str.lower().str.strip()
    df["status"] = df["status"].astype(str).str.lower().str.strip()
    df["source_ip"] = df["source_ip"].astype(str).str.strip()
    df["username"] = df["username"].astype(str).str.strip()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    failed = df[(df["event_type"].isin(["login", "authentication", "auth"])) &
                (df["status"].isin(["failed", "failure", "denied"]))]
    failed_counts = failed.groupby("source_ip").size().to_dict()

    alerts = []
    for ip, count in failed_counts.items():
        if count >= 5:
            alerts.append({
                "timestamp": "Multiple events",
                "source_ip": ip,
                "username": ", ".join(sorted(set(failed.loc[failed.source_ip == ip, "username"]))),
                "event_type": "Repeated failed logins",
                "status": "failed",
                "severity": "HIGH",
                "reason": f"{count} failed login attempts from this IP",
                "recommendation": "Review authentication logs; verify the user and source IP; consider temporary controls under an approved policy."
            })
        elif count >= 3:
            alerts.append({
                "timestamp": "Multiple events",
                "source_ip": ip,
                "username": ", ".join(sorted(set(failed.loc[failed.source_ip == ip, "username"]))),
                "event_type": "Repeated failed logins",
                "status": "failed",
                "severity": "MEDIUM",
                "reason": f"{count} failed login attempts from this IP",
                "recommendation": "Review recent login activity and confirm whether the attempts are expected."
            })

    suspicious = df[df["event_type"].isin(["malware_detected", "malware", "privilege_escalation", "unauthorized_access", "suspicious_process"])]
    for _, row in suspicious.iterrows():
        alerts.append({
            "timestamp": str(row["timestamp"]) if pd.notna(row["timestamp"]) else "Unknown",
            "source_ip": row["source_ip"],
            "username": row["username"],
            "event_type": row["event_type"],
            "status": row["status"],
            "severity": "HIGH" if row["event_type"] in ["malware_detected", "malware", "privilege_escalation"] else "MEDIUM",
            "reason": f"Security event flagged: {row['event_type']}",
            "recommendation": "Validate the event, preserve relevant logs, and follow your organization's incident-response procedure."
        })

    alerts_df = pd.DataFrame(alerts, columns=[
        "timestamp", "source_ip", "username", "event_type", "status",
        "severity", "reason", "recommendation"
    ])
    return df, alerts_df

sample = pd.DataFrame([
    ["2026-10-28 09:01:00", "192.0.2.10", "student", "login", "success"],
    ["2026-10-28 09:02:00", "198.51.100.23", "admin", "login", "failed"],
    ["2026-10-28 09:02:10", "198.51.100.23", "admin", "login", "failed"],
    ["2026-10-28 09:02:20", "198.51.100.23", "admin", "login", "failed"],
    ["2026-10-28 09:02:30", "198.51.100.23", "admin", "login", "failed"],
    ["2026-10-28 09:02:40", "198.51.100.23", "admin", "login", "failed"],
    ["2026-10-28 09:05:00", "203.0.113.7", "analyst", "malware_detected", "alert"],
    ["2026-10-28 09:08:00", "192.0.2.15", "guest", "login", "success"],
    ["2026-10-28 09:10:00", "203.0.113.9", "operator", "unauthorized_access", "alert"],
], columns=["timestamp", "source_ip", "username", "event_type", "status"])

st.sidebar.header("Log input")
uploaded = st.sidebar.file_uploader("Upload a CSV log file", type=["csv"])
st.sidebar.write("Required columns:")
st.sidebar.code("timestamp, source_ip, username, event_type, status")
st.sidebar.caption("Use only logs you are authorized to analyze.")

try:
    data = pd.read_csv(uploaded) if uploaded else sample
    analyzed, alerts = analyze_logs(data)
except Exception as exc:
    st.error(f"Could not analyze this file: {exc}")
    st.info("Check the required column names and upload a valid CSV.")
    st.stop()

total_events = len(analyzed)
high = int((alerts["severity"] == "HIGH").sum()) if not alerts.empty else 0
medium = int((alerts["severity"] == "MEDIUM").sum()) if not alerts.empty else 0
failed_count = int(analyzed["status"].isin(["failed", "failure", "denied"]).sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", total_events)
c2.metric("Alerts generated", len(alerts))
c3.metric("High severity", high)
c4.metric("Failed events", failed_count)

st.subheader("Security alerts")
if alerts.empty:
    st.success("No alerts were generated by the current demonstration rules.")
else:
    st.dataframe(alerts, use_container_width=True, hide_index=True)
    st.download_button("Download alerts as CSV", alerts.to_csv(index=False).encode("utf-8"),
                       file_name="soc_alerts.csv", mime="text/csv")

left, right = st.columns(2)
with left:
    st.subheader("Events by type")
    st.bar_chart(analyzed["event_type"].value_counts())
with right:
    st.subheader("Events by status")
    st.bar_chart(analyzed["status"].value_counts())

st.subheader("Raw events")
st.dataframe(analyzed, use_container_width=True, hide_index=True)

st.warning("Prototype limitation: this version uses transparent rules, not a trained AI model. It does not automatically block IP addresses or change systems. Treat alerts as leads for human review.")
