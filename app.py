"""
SOC Sentinel - Interactive SOC Log Monitoring & Threat Detection Platform.
Streamlit Command Center with Real-Time Telemetry, Incident Triage, and Threat Intelligence.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from pathlib import Path
import json
import sys

# Ensure UTF-8 output
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from src.database.db_manager import DatabaseManager
from src.ingestion.normalizer import LogNormalizer
from src.detection.engine import DetectionEngine
from src.enrichment.threat_intel import ThreatIntelService
from src.simulator.traffic_generator import TrafficSimulator
from src.utils.report_generator import IncidentReportGenerator

# ---------------- PAGE CONFIGURATION ----------------
st.set_page_config(
    page_title="SOC Sentinel | SIEM Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- CUSTOM CYBERPUNK / SOC STYLING ----------------
st.markdown("""
<style>
    /* Dark cyber background and accents */
    .stApp {
        background-color: #0b0f19;
        color: #e0e6ed;
    }
    
    /* Top Banner */
    .soc-header {
        background: linear-gradient(90deg, #11192e 0%, #172a4d 50%, #0d1527 100%);
        padding: 20px 24px;
        border-radius: 12px;
        border: 1px solid #1f355b;
        box-shadow: 0 4px 20px rgba(0, 200, 255, 0.08);
        margin-bottom: 20px;
    }
    .soc-title {
        font-family: 'Segoe UI', monospace, sans-serif;
        font-size: 28px;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #00e5ff;
        margin: 0;
        text-shadow: 0 0 10px rgba(0, 229, 255, 0.4);
    }
    .soc-subtitle {
        color: #8da2c0;
        font-size: 14px;
        margin-top: 4px;
        font-family: monospace;
    }
    
    /* Metric Cards */
    .metric-card {
        background-color: #131c2e;
        border: 1px solid #223759;
        border-radius: 10px;
        padding: 16px 20px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.4);
    }
    .metric-value {
        font-size: 28px;
        font-weight: 700;
        color: #ffffff;
        font-family: monospace;
    }
    .metric-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #7b93b2;
        margin-top: 4px;
    }
    
    /* Severity Badges */
    .badge-critical {
        background-color: rgba(255, 23, 68, 0.2);
        color: #ff1744;
        border: 1px solid #ff1744;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-high {
        background-color: rgba(255, 145, 0, 0.2);
        color: #ff9100;
        border: 1px solid #ff9100;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-medium {
        background-color: rgba(255, 214, 0, 0.2);
        color: #ffd600;
        border: 1px solid #ffd600;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-low {
        background-color: rgba(0, 229, 255, 0.2);
        color: #00e5ff;
        border: 1px solid #00e5ff;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-info {
        background-color: rgba(0, 230, 118, 0.2);
        color: #00e676;
        border: 1px solid #00e676;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    
    /* Incident Card Box */
    .incident-box {
        background-color: #111b2d;
        border-left: 4px solid #00e5ff;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
</style>
""", unsafe_allow_html=True)

# ---------------- INITIALIZATION ----------------
@st.cache_resource
def get_services():
    db = DatabaseManager()
    normalizer = LogNormalizer()
    engine = DetectionEngine(db)
    threat_intel = ThreatIntelService(db)
    return db, normalizer, engine, threat_intel

db, normalizer, engine, threat_intel = get_services()

# Auto-seed if database is empty
telemetry = db.get_telemetry_metrics()
if telemetry["total_events"] == 0:
    base_dir = Path(__file__).resolve().parent
    ti_path = base_dir / "data" / "threat_intel" / "malicious_ips.json"
    if ti_path.exists():
        db.load_threat_intel_iocs(ti_path)
    sample_dir = base_dir / "data" / "sample_logs"
    all_sample_events = []
    for f in [sample_dir / "auth.log", sample_dir / "web_access.log", sample_dir / "firewall.csv", sample_dir / "windows_events.json"]:
        if f.exists():
            all_sample_events.extend(normalizer.parse_file(f))
    if all_sample_events:
        db.insert_events(all_sample_events)
        engine.analyze_events(all_sample_events, persist=True)
    telemetry = db.get_telemetry_metrics()

# ---------------- TOP HEADER ----------------
st.markdown("""
<div class="soc-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1 class="soc-title">🛡️ SOC SENTINEL | SIEM & THREAT DETECTION</h1>
            <div class="soc-subtitle">Security Information & Event Management • MITRE ATT&CK Correlated • Incident Response</div>
        </div>
        <div style="text-align: right;">
            <span style="background-color: #00e67622; color: #00e676; border: 1px solid #00e676; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; font-family: monospace;">
                ● LIVE SOC PIPELINE ACTIVE
            </span>
            <div style="color: #64748b; font-size: 11px; margin-top: 6px; font-family: monospace;">
                ENGINE VER: 2.4.0-PROD
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR NAVIGATION ----------------
st.sidebar.markdown("""
<div style="text-align: center; margin-bottom: 15px;">
    <div style="display: inline-block; background: linear-gradient(135deg, #00e5ff22, #7c4dff22); border: 2px solid #00e5ff; border-radius: 50%; padding: 16px; box-shadow: 0 0 15px rgba(0, 229, 255, 0.4);">
        <span style="font-size: 38px;">🛡️</span>
    </div>
</div>
""", unsafe_allow_html=True)
st.sidebar.title("SOC Analyst Portal")
st.sidebar.markdown("**Active Analyst:** `Tier-2 SOC Specialist`")
st.sidebar.markdown(f"**Host:** `WIN-SOC-WORKSTATION`")
st.sidebar.divider()

nav_choice = st.sidebar.radio(
    "Navigation Console",
    [
        "🛡️ Executive Overview",
        "🚨 Alert Triage & Workbench",
        "🔍 SIEM Log Hunter",
        "🌐 Threat Intel & IOC Explorer",
        "⚡ Live Attack Simulator",
        "📄 Incident Forensics Report"
    ]
)

st.sidebar.divider()
st.sidebar.markdown("### 📊 Live SIEM Status")
st.sidebar.info(f"**Total Events:** {telemetry['total_events']:,}\n\n**Active Alerts:** {telemetry['active_alerts']}\n\n**Critical Severity:** {telemetry['critical_alerts']}")

if st.sidebar.button("🔄 Refresh Telemetry"):
    st.rerun()

# ==============================================================================
# TAB 1: EXECUTIVE OVERVIEW
# ==============================================================================
if nav_choice == "🛡️ Executive Overview":
    st.subheader("Executive SOC Dashboard & Threat Telemetry")

    # Top KPI Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #00e5ff;">{telemetry['total_events']:,}</div>
            <div class="metric-label">Total Ingested Events</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ff9100;">{telemetry['total_alerts']}</div>
            <div class="metric-label">Total Detections</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ff1744;">{telemetry['critical_alerts']}</div>
            <div class="metric-label">Critical Threat Alerts</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #00e676;">{telemetry['blocked_ips']}</div>
            <div class="metric-label">Contained Adversaries</div>
        </div>
        """, unsafe_allow_html=True)
    with m5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #b388ff;">1.2s</div>
            <div class="metric-label">Mean Time To Detect</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts Row
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("#### 🚨 Detections by Severity")
        sev_counts = telemetry["severity_counts"]
        if sev_counts:
            sev_df = pd.DataFrame(list(sev_counts.items()), columns=["Severity", "Count"])
            color_map = {
                "CRITICAL": "#ff1744",
                "HIGH": "#ff9100",
                "MEDIUM": "#ffd600",
                "LOW": "#00e5ff",
                "INFO": "#00e676"
            }
            fig_donut = px.pie(
                sev_df, values="Count", names="Severity", hole=0.55,
                color="Severity", color_discrete_map=color_map
            )
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#cbd5e1"),
                margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2)
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No alert data available.")

    with c2:
        st.markdown("#### 🎯 MITRE ATT&CK Tactic Distribution")
        mitre_data = telemetry["mitre_tactics"]
        if mitre_data:
            mitre_df = pd.DataFrame(list(mitre_data.items()), columns=["Tactic", "Alerts"]).sort_values(by="Alerts", ascending=True)
            fig_bar = px.bar(
                mitre_df, x="Alerts", y="Tactic", orientation="h",
                color="Alerts", color_continuous_scale="Viridis"
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#cbd5e1"),
                margin=dict(t=20, b=20, l=20, r=20),
                xaxis=dict(gridcolor="#1e293b"),
                yaxis=dict(gridcolor="#1e293b")
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No MITRE tactics recorded.")

    # Timeline Row
    st.markdown("#### 📈 Event Activity & Ingestion Volume")
    timeline = telemetry["timeline_data"]
    if timeline:
        t_df = pd.DataFrame(timeline)
        fig_time = px.line(t_df, x="time", y="count", markers=True, line_shape="spline", color_discrete_sequence=["#00e5ff"])
        fig_time.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#cbd5e1"),
            xaxis=dict(title="Timestamp (Hour Bucket)", gridcolor="#1e293b"),
            yaxis=dict(title="Normalized Events", gridcolor="#1e293b"),
            margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_time, use_container_width=True)

    # Recent Alerts Summary Table
    st.markdown("#### ⚡ Active Security Alert Feed")
    recent_alerts = db.get_alerts(limit=5)
    if recent_alerts:
        feed_data = []
        for a in recent_alerts:
            feed_data.append({
                "ID": a["id"],
                "Severity": a["severity"],
                "Rule": a["rule_name"],
                "Adversary IP": a["source_ip"] or "Local",
                "Target": a["user"] or a["dest_ip"] or "Host",
                "MITRE Technique": f"{a['mitre_technique_id']} ({a['mitre_technique_name']})",
                "Status": a["status"]
            })
        st.dataframe(pd.DataFrame(feed_data), use_container_width=True, hide_index=True)
    else:
        st.success("No active security incidents.")

# ==============================================================================
# TAB 2: ALERT TRIAGE & INCIDENT WORKBENCH
# ==============================================================================
elif nav_choice == "🚨 Alert Triage & Workbench":
    st.subheader("SOC Incident Case Management & Triage")
    st.markdown("Review detected security events, inspect raw forensic evidence, update triage states, and apply remediation playbooks.")

    # Filters
    f1, f2 = st.columns([1, 1])
    with f1:
        status_filter = st.selectbox("Filter by Status", ["All", "New", "Investigating", "Contained", "Resolved", "False Positive"])
    with f2:
        severity_filter = st.selectbox("Filter by Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    alerts = db.get_alerts(status=status_filter, severity=severity_filter, limit=100)

    st.write(f"Displaying **{len(alerts)}** matching security alerts:")

    if not alerts:
        st.info("No security alerts matching current filter parameters.")

    for alert in alerts:
        sev = alert["severity"]
        badge_class = f"badge-{sev.lower()}"
        status_color = "#ff1744" if alert["status"] == "New" else ("#ff9100" if alert["status"] == "Investigating" else ("#00e5ff" if alert["status"] == "Contained" else "#00e676"))

        expander_title = f"[{sev}] #{alert['id']} - {alert['title']} | Target: {alert['user'] or alert['dest_ip']} | Status: {alert['status']}"

        with st.expander(expander_title, expanded=(alert["status"] == "New" and sev == "CRITICAL")):
            st.markdown(f"""
            <div style="background-color: #162238; padding: 12px 16px; border-radius: 8px; margin-bottom: 12px; border: 1px solid #23385d;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="{badge_class}">{sev}</span>
                        <span style="background-color: {status_color}22; color: {status_color}; border: 1px solid {status_color}; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; margin-left: 8px;">
                            STATUS: {alert['status'].upper()}
                        </span>
                        <span style="color: #94a3b8; font-size: 12px; margin-left: 12px; font-family: monospace;">
                            MITRE ATT&CK: <strong>{alert['mitre_technique_id']}</strong> ({alert['mitre_tactic']})
                        </span>
                    </div>
                    <div style="color: #94a3b8; font-size: 12px; font-family: monospace;">
                        Events Correlated: <strong>{alert['event_count']}</strong>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_info1, col_info2 = st.columns(2)
            with col_info1:
                st.markdown(f"**Adversary / Source IP:** `{alert['source_ip'] or 'Internal'}`")
                st.markdown(f"**Target User Account:** `{alert['user'] or 'N/A'}`")
                st.markdown(f"**Destination Asset:** `{alert['dest_ip'] or 'Internal Server'}`")
            with col_info2:
                st.markdown(f"**First Detected:** `{alert['first_seen']}`")
                st.markdown(f"**Last Updated:** `{alert['updated_at']}`")
                st.markdown(f"**Detection Rule:** `{alert['rule_name']}`")

            st.markdown("##### 📝 Threat Analysis Description")
            st.markdown(f"> {alert['description']}")

            st.markdown("##### 🛡️ Recommended Containment Playbook")
            st.code(alert["recommended_action"] or "Follow standard Tier-1 isolation protocol.", language="text")

            # Evidence Section
            st.markdown("##### 🔬 Forensic Evidence & Log Artifacts")
            try:
                evidence = json.loads(alert["evidence_json"])
            except Exception:
                evidence = [alert["evidence_json"]]
            
            if isinstance(evidence, list) and evidence:
                evidence_text = "\n".join(evidence)
                st.text_area("Correlated Log Entries", value=evidence_text, height=120, disabled=True, key=f"ev_{alert['id']}")
            else:
                st.caption("No direct raw log entries attached.")

            # Analyst Triage Form
            st.markdown("##### ✍️ Analyst Incident Disposition")
            with st.form(key=f"triage_form_{alert['id']}"):
                t_col1, t_col2 = st.columns([1, 2])
                with t_col1:
                    new_status = st.selectbox(
                        "Update Status",
                        ["New", "Investigating", "Contained", "Resolved", "False Positive"],
                        index=["New", "Investigating", "Contained", "Resolved", "False Positive"].index(alert["status"]) if alert["status"] in ["New", "Investigating", "Contained", "Resolved", "False Positive"] else 0,
                        key=f"st_{alert['id']}"
                    )
                with t_col2:
                    analyst_notes = st.text_input(
                        "Analyst Notes / Incident Log",
                        value=alert["analyst_notes"] or "",
                        placeholder="e.g. Blocked IP on firewall, user confirmed travel...",
                        key=f"notes_{alert['id']}"
                    )

                submit_triage = st.form_submit_button("💾 Save Case Updates")
                if submit_triage:
                    db.update_alert_status(alert["id"], new_status, analyst_notes)
                    st.success(f"Case #{alert['id']} updated successfully!")
                    st.rerun()

# ==============================================================================
# TAB 3: SIEM LOG HUNTER
# ==============================================================================
elif nav_choice == "🔍 SIEM Log Hunter":
    st.subheader("SIEM Threat Hunting & Log Search")
    st.markdown("Explore normalized security telemetry across all endpoints, firewalls, web servers, and authentication systems.")

    # Search and Filter Toolbar
    c_s1, c_s2, c_s3 = st.columns([2, 1, 1])
    with c_s1:
        search_kw = st.text_input("Search Logs (IP, Username, URI, Action, Regex)", placeholder="e.g. 192.0.2.100 or 'root' or 'UNION SELECT'")
    with c_s2:
        type_filter = st.selectbox("Event Category", ["All", "AUTHENTICATION", "WEB", "NETWORK", "SYSTEM"])
    with c_s3:
        max_rows = st.selectbox("Result Limit", [50, 100, 250, 500], index=1)

    events = db.get_events(query_filter=search_kw, event_type=type_filter, limit=max_rows)

    st.write(f"Showing **{len(events)}** normalized security events:")

    if events:
        df = pd.DataFrame(events)
        display_cols = ["timestamp", "source_ip", "dest_ip", "dest_port", "user", "action", "status", "event_type", "severity_hint", "raw_log"]
        
        # Color-coded severity preview
        st.dataframe(
            df[display_cols],
            use_container_width=True,
            hide_index=True
        )

        # Download CSV
        csv_data = df.to_csv(index=False)
        st.download_button(
            label="📥 Export Query Results to CSV",
            data=csv_data,
            file_name=f"soc_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.warning("No normalized events matched the search criteria.")

# ==============================================================================
# TAB 4: THREAT INTEL & IOC EXPLORER
# ==============================================================================
elif nav_choice == "🌐 Threat Intel & IOC Explorer":
    st.subheader("Threat Intelligence & Adversary Profiling")
    st.markdown("Correlate suspicious external IPs against integrated threat feeds, C2 tracker databases, and known adversary infrastructure.")

    known_iocs = ["198.51.100.23", "203.0.113.45", "192.0.2.100", "185.220.101.5", "45.33.32.156"]
    
    col_input1, col_input2 = st.columns([2, 1])
    with col_input1:
        target_ip = st.text_input("Enter IP Address to Investigate", value="198.51.100.23")
    with col_input2:
        st.markdown("<br>", unsafe_allow_html=True)
        quick_select = st.selectbox("Or Quick-Select Known IOC:", ["Select an IP..."] + known_iocs)
        if quick_select != "Select an IP...":
            target_ip = quick_select

    if target_ip:
        rep = threat_intel.get_ip_reputation(target_ip)
        geo = rep.get("geo", {})

        st.markdown("---")
        # Reputation Card
        rep_color = "#ff1744" if rep["reputation"] == "MALICIOUS" else ("#00e676" if rep["reputation"] == "TRUSTED INTERNAL" else "#ff9100")

        st.markdown(f"""
        <div style="background-color: #141f33; border: 1px solid {rep_color}; border-radius: 10px; padding: 20px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h2 style="margin: 0; color: #ffffff; font-family: monospace;">IP: {target_ip}</h2>
                    <div style="color: #94a3b8; font-size: 14px; margin-top: 4px;">
                        Associated Threat Actor: <strong>{rep['threat_actor']}</strong>
                    </div>
                </div>
                <div style="text-align: right;">
                    <span style="background-color: {rep_color}22; color: {rep_color}; border: 1px solid {rep_color}; padding: 6px 14px; border-radius: 6px; font-weight: 800; font-size: 16px;">
                        {rep['reputation']}
                    </span>
                    <div style="color: #cbd5e1; font-size: 14px; margin-top: 6px; font-family: monospace;">
                        Risk Confidence: <strong>{rep['risk_score']}%</strong>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_g1, col_g2, col_g3 = st.columns(3)
        with col_g1:
            st.markdown("#### 🌍 Geolocation Telemetry")
            st.markdown(f"**Country:** `{geo.get('country')} ({geo.get('code')})`")
            st.markdown(f"**City:** `{geo.get('city')}`")
            st.markdown(f"**Coordinates:** `{geo.get('lat')}, {geo.get('lon')}`")
        with col_g2:
            st.markdown("#### 🏢 Autonomous System & ISP")
            st.markdown(f"**ASN:** `{geo.get('asn')}`")
            st.markdown(f"**Internet Provider:** `{geo.get('isp')}`")
            st.markdown(f"**Threat Category:** `{rep['threat_type']}`")
        with col_g3:
            st.markdown("#### 🏷️ Threat Intelligence Tags")
            for t in rep.get("tags", []):
                st.markdown(f"- `{t}`")

        # Local Correlated Events
        st.markdown("#### 📂 Correlated Events Involving this IP")
        related = db.get_events(query_filter=target_ip, limit=50)
        if related:
            st.write(f"Found **{len(related)}** related events in current SIEM logs:")
            st.dataframe(pd.DataFrame(related)[["timestamp", "action", "status", "event_type", "raw_log"]], use_container_width=True, hide_index=True)
        else:
            st.info("No recorded activity from this IP in the current dataset.")

# ==============================================================================
# TAB 5: LIVE ATTACK SIMULATOR & INGESTION
# ==============================================================================
elif nav_choice == "⚡ Live Attack Simulator":
    st.subheader("Live Adversary Simulation & Custom Ingestion")
    st.markdown("Simulate active cyber attacks against internal services to demonstrate real-time detection, sliding-window correlation, and alerting.")

    col_s1, col_s2 = st.columns([1, 1])

    with col_s1:
        st.markdown("### 🎯 Attack Scenario Injector")
        st.markdown("Select a multi-stage attack campaign and inject it directly into the SOC monitoring pipeline:")

        scenario = st.selectbox(
            "Select Attack Scenario",
            [
                ("SSH_BRUTE_FORCE", "🚨 SSH Credential Brute-Force & Compromise (T1110)"),
                ("PORT_SCAN", "🔍 Network Reconnaissance / SYN Port Sweep (T1046)"),
                ("WEB_SQLI_ATTACK", "💉 Web Exploitation: SQL Injection & LFI (T1190)"),
                ("SUDO_PRIV_ESCALATION", "⚡ Unauthorized Sudo Shell Privilege Escalation (T1548.003)")
            ],
            format_func=lambda x: x[1]
        )

        if st.button("🚀 Execute Attack Simulation", type="primary"):
            new_events = TrafficSimulator.generate_attack_campaign(scenario[0])
            db.insert_events(new_events)
            new_alerts = engine.analyze_events(new_events, persist=True)
            st.success(f"Injected {len(new_events)} attack events into pipeline! Triggered {len(new_alerts)} security alerts.")
            st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### 🟢 Benign Traffic Generator")
        st.markdown("Generate normal user activity to test SIEM noise filtering and false positive resilience.")
        benign_count = st.slider("Number of Benign Events to Inject", 5, 50, 15)
        if st.button("Generate Benign Traffic"):
            benign_events = TrafficSimulator.generate_benign_traffic(benign_count)
            db.insert_events(benign_events)
            st.success(f"Generated {len(benign_events)} benign events.")
            st.rerun()

    with col_s2:
        st.markdown("### 📥 Custom Log File Upload")
        st.markdown("Upload any Linux `auth.log`, Apache/Nginx web access log, Firewall `.csv`, or Windows `.json`:")

        uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt", "csv", "json"])
        if uploaded_file is not None:
            raw_text = uploaded_file.read().decode("utf-8", errors="replace")
            st.text_area("File Preview", value=raw_text[:400] + "...", height=120, disabled=True)

            if st.button("📥 Parse & Ingest Uploaded Log"):
                parsed_events = []
                if uploaded_file.name.endswith(".json"):
                    parsed_events = normalizer.windows_parser.parse_file(Path(uploaded_file.name)) # fallback or parse text
                    # parse json text
                    try:
                        data = json.loads(raw_text)
                        if isinstance(data, list):
                            for item in data:
                                evt = normalizer.windows_parser.parse_event(item)
                                if evt: parsed_events.append(evt)
                    except Exception as e:
                        st.error(f"JSON parsing error: {e}")
                else:
                    parsed_events = normalizer.parse_raw_text(raw_text, log_type="auto")

                if parsed_events:
                    db.insert_events(parsed_events)
                    uploaded_alerts = engine.analyze_events(parsed_events, persist=True)
                    st.success(f"Ingested {len(parsed_events)} events. Triggered {len(uploaded_alerts)} security alerts!")
                    st.rerun()
                else:
                    st.warning("Could not identify or parse valid security events from this file format.")

        st.divider()
        st.markdown("### 🧹 Database Reset")
        if st.button("Reset SIEM Data to Baseline Sample"):
            db.clear_all()
            base_dir = Path(__file__).resolve().parent
            ti_path = base_dir / "data" / "threat_intel" / "malicious_ips.json"
            if ti_path.exists():
                db.load_threat_intel_iocs(ti_path)
            sample_dir = base_dir / "data" / "sample_logs"
            all_sample_events = []
            for f in [sample_dir / "auth.log", sample_dir / "web_access.log", sample_dir / "firewall.csv", sample_dir / "windows_events.json"]:
                if f.exists():
                    all_sample_events.extend(normalizer.parse_file(f))
            if all_sample_events:
                db.insert_events(all_sample_events)
                engine.analyze_events(all_sample_events, persist=True)
            st.success("Database reset to baseline dataset.")
            st.rerun()

# ==============================================================================
# TAB 6: INCIDENT FORENSICS REPORT GENERATOR
# ==============================================================================
elif nav_choice == "📄 Incident Forensics Report":
    st.subheader("SOC Incident Forensics & Executive Briefing Generator")
    st.markdown("Produce audit-ready, executive-grade SOC incident reports for CISOs, leadership, and regulatory documentation.")

    all_alerts = db.get_alerts(limit=100)
    if not all_alerts:
        st.warning("No incidents available to generate reports. Please ingest logs or simulate attacks first.")
    else:
        alert_options = {f"#{a['id']} - [{a['severity']}] {a['title']}": a for a in all_alerts}
        selected_title = st.selectbox("Select Security Incident to Report:", list(alert_options.keys()))

        selected_alert = alert_options[selected_title]
        rep_intel = threat_intel.get_ip_reputation(selected_alert["source_ip"]) if selected_alert["source_ip"] else None

        markdown_report = IncidentReportGenerator.generate_markdown_report(selected_alert, rep_intel)

        col_rep1, col_rep2 = st.columns([3, 1])
        with col_rep1:
            st.markdown("### 📋 Executive Incident Report Preview")
        with col_rep2:
            st.download_button(
                label="📥 Download Markdown Report",
                data=markdown_report,
                file_name=f"INCIDENT_REPORT_{selected_alert['id']}_{datetime.now().strftime('%Y%m%d')}.md",
                mime="text/markdown",
                type="primary"
            )

        st.markdown(markdown_report)
