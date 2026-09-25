# 🛡️ BloodHoundLite

[![Python 3.x](https://img.shields.io/badge/Python-3.x-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux / Kali](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-blue?style=flat&logo=linux&logoColor=white)](https://www.kali.org/)

A lightweight yet powerful Active Directory data analysis and relationship mapping tool engineered specifically for resource-constrained environments (such as virtualized Kali Linux instances running on limited RAM and storage).

`BloodHoundLite` ingests raw BloodHound JSON datasets (collected via SharpHound or BloodHound.py), parses complex graph structures, identifies high-value attack paths, queries node properties, and renders interactive HTML attack graphs—all without requiring heavy background database services like Neo4j.

---

## 🌟 Key Features

- **Multi-Format Data Ingestion:** Directly parses `.json` files, directories containing multiple JSON files, or compressed `.zip` archives output by standard collectors.
- **Automated Attack Pathfinding:** Computes the shortest attack trajectory between an initial compromise vector and a domain target using NetworkX graph algorithms.
- **Property-Based Node Querying:** Quickly search domain objects filtered by object type (`User`, `Group`, `Computer`), operating system versions, account status (`Enabled: True/False`), or custom attributes.
- **Relationship & Permission Inspection:** Enumerate all incoming and outgoing AD relationships (e.g., `MemberOf`, `HasSession`, `AdminTo`, `GenericAll`) for any given SID or domain object.
- **Interactive Visual Reporting:** Renders clean, self-contained HTML graph reports via PyVis, complete with color-coded nodes (*Users: Blue*, *Groups: Green*, *Computers: Red*) and hoverable metadata tooltips.

---

## 🎯 Practical Application & Lab Validation

This tool was designed and tested in hands-on enterprise Active Directory lab assessments, including:
- **TryHackMe:** *Post-Exploitation Basics* (mapping privilege escalation paths, user rights, and Kerberoastable targets).
- **Custom Local Cyber Labs:** Rapid post-exploitation recon without agent footprints or Neo4j memory overhead.

---

## ⚙️ System Requirements

- **Operating System:** Optimized for Linux distributions (Kali Linux, Debian, Ubuntu) and cross-platform compatible.
- **RAM:** Minimum 2GB (5GB recommended for heavy enterprise domain datasets).
- **Storage:** ~1GB free space for scripts and generated HTML reports.
- **Python:** Python 3.8+

---

## 🚀 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/Subir-T/bloodhound_lite.git](https://github.com/Subir-T/bloodhound_lite.git)
   cd bloodhound_lite
