
# 📡 **Network Traffic Analyzer**

*A Streamlit-powered tool for PCAP analysis, anomaly insights, and traffic visualization.*



## 📘 **Overview**

**Network Traffic Analyzer** is a Python + Streamlit application designed to:

* Analyze **PCAP** files
* Visualize **protocol distributions**
* Show **top IP communications**
* Detect **suspicious flows**
* Provide **AI-based summaries**
* Simulate **live packet replay**
* Generate **synthetic attacks** using Scapy

This project demonstrates essential **computer networking** and **cybersecurity** concepts through a clean, interactive dashboard.


# 🚀 **Features**

### 🔍 **Traffic Analysis**

* Upload & analyze **PCAP / PCAPNG**
* Inspect **TCP / UDP / ICMP / ARP / IP** traffic
* Identify **source → destination** flows
* Detect frequently targeted **ports**
* Calculate **total bandwidth usage**



### 📊 **Visualizations**

* **Protocol distribution** chart
* **IP communication** bar graphs
* **Port distribution** charts
* Interactive tables and metrics
* Custom dark-themed UI with CSS



### 🧠 **AI Insights**

* Rule-based summary generator
* Risk scoring (0–100)
* **Low / Medium / High** threat classification
* Automatic identification of suspicious flows



### 🛠 **Attack Simulation (Scapy)**

* **TCP Port Scan**
* **UDP Flood**
* **ICMP Sweep**
* **ARP Spoofing**
* Generates realistic `fake_attack.pcap` for testing



### ▶️ **Simulated Live Replay**

* Packet-by-packet replay of PCAP files
* Adjustable replay speed
* Useful for demos, teaching, and understanding flow behavior



### 📁 **Export Options**

Export results as:

* **CSV**
* **JSON**

Includes:

* Protocol distribution
* IP communication table



# 🗂 **Project Structure**

```
network-traffic-analysis/
│
├── .streamlit/
│   └── config.toml
│
├── analyzer/
│   └── traffic_analyzer.py
│
├── data/
│   └── fake_attack.pcap
│
├── app.py
├── main.py
├── generate_sample_pcap.py
├── requirements.txt
└── .gitignore
```

---

# 🛠 **Installation**

### **1️⃣ Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/network-traffic-analysis.git
cd network-traffic-analysis
```

### **2️⃣ Create virtual environment**

```bash
python -m venv .venv
```

### **3️⃣ Activate virtual environment**

**Windows:**

```bash
.venv\Scripts\activate
```

**Mac/Linux:**

```bash
source .venv/bin/activate
```

### **4️⃣ Install dependencies**

```bash
pip install -r requirements.txt
```

---

# ▶️ **Running the Application**

### **Run the Streamlit Dashboard**

```bash
streamlit run app.py
```

### **Generate a Fake Attack PCAP**

```bash
python generate_sample_pcap.py
```

### **Optional: Use CLI Analyzer**

```bash
python main.py data/fake_attack.pcap --visualize
```

---

#  **Networking Concepts Used**

* Packet capture (**PCAP**) processing
* OSI model (Layers **2–4**)
* Protocol inspection (**TCP/UDP/ICMP/ARP**)
* Port-based traffic analysis
* IP flow tracking
* Bandwidth calculation
* Attack simulation
* Traffic replay
* Basic rule-based anomaly detection


---

# 🚀 **Recent Improvements (v2 Upgrade)**

This project has been enhanced to improve usability, clarity, and analytical capabilities.

---

## ✨ **UI & Dashboard Enhancements**

* Added structured **sidebar navigation** for better user experience
* Organized dashboard into clear sections:

  * Overview
  * Traffic Analysis
  * AI Insights
* Improved layout for better readability and interaction

---

## 📊 **Enhanced Visualizations**

* Integrated more **interactive charts** using Plotly
* Improved:

  * Protocol distribution visualization
  * IP communication graphs
  * Port activity insights
* Added better data presentation for faster interpretation

---

## 🤖 **Improved Risk Scoring System**

* Refined rule-based **risk scoring logic**

* Risk now calculated based on:

  * Unusual port usage
  * High-frequency packet activity
  * Suspicious IP behavior

* Added clear output:

  * **Risk Score (0–100)**
  * **Threat Level (Low / Medium / High)**
  * **Reason for classification**

---

## 💡 **AI-Based Insight Improvements**

* Enhanced explanation system for detected anomalies
* System now provides **human-readable insights**, such as:

  * Possible port scanning
  * Unusual traffic spikes
  * Suspicious communication patterns

---

## 📁 **Sample Data & Testing**

* Added sample PCAP (`fake_attack.pcap`) for testing and demonstration
* Improved reproducibility of results
* Enables quick project evaluation without external data

---

## 📸 **Documentation Improvements**

* Improved project documentation structure
* Added clearer explanations of features and workflow
* Prepared for inclusion of:

  * Screenshots
  * Demo visuals

---

## ⚠️ **Note on Real-Time Detection**

This project currently focuses on **offline PCAP-based analysis**.

* Designed for:

  * Network traffic investigation
  * Post-event analysis
  * Anomaly detection

🔮 Real-time detection is planned as a future enhancement.

---

## 🔄 **Project Evolution**

**Version 1:**

* Basic PCAP analysis
* Static visualizations
* Initial rule-based detection

**Version 2 (Current):**

* Improved UI/UX
* Enhanced visualization
* Refined risk scoring
* Better AI insights and explanations

---


#  **Future Enhancements**

* **Real-time live sniffing**
* **Machine Learning–based anomaly detection**
* **Threat Intelligence integration** (e.g., AbuseIPDB, Shodan)
* **Device fingerprinting**
* **PDF report generation**
* **Multi-page dashboard redesign**
* **Cloud deployment** (Streamlit Cloud / Render / AWS)



# 📜 **License**

Licensed under the **MIT License**.


# 🤝 **Contributing**

Contributions are welcome.
Open an issue or submit a pull request to improve features or documentation.



# 📧 **Contact**

For questions, suggestions, or collaboration:


*sara510official@gmail.com*



