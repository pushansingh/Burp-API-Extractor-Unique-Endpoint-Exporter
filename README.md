# 🚀 Burp API Extractor – Unique Endpoint Exporter

**Burp API Extractor** is a powerful **Burp Suite extension** designed to extract, analyze, and export **unique API endpoints** from **Proxy History** or **Repeater**.

It makes API discovery effortless by:
- 🧹 Removing unnecessary parameters  
- 🔄 Normalizing dynamic paths  
- 📤 Exporting in multiple formats (**CSV**, **Postman v2.1**, **JSON**, **Swagger/OpenAPI**)  
- 🧠 Introducing **API Delta**: a feature to compare two API datasets to highlight unique and common endpoints  

---

## 🔍 Why Use Burp API Extractor?

- **Simplified API Discovery**  
  → Clean, structured, normalized endpoints from noisy traffic  
- **Automated Filtering**  
  → Filter by domain, HTTP method, or dynamic segments  
- **Multiple Export Options**  
  → CSV, JSON, Postman (v2.1), Swagger (coming soon!)  
- **Enhanced Testing Workflow**  
  → Export-ready data for documentation, validation, or analysis  

---

## 👥 Who’s It For?

This extension is perfect for:
- 🛡 **Penetration Testers** – Quickly extract endpoints for security testing  
- 👨‍💻 **Developers & QA** – Document and validate APIs easily  
- 🐞 **Bug Bounty Hunters** – Surface potential vulnerabilities  
- 📊 **API Analysts** – Use **API Delta** to compare and analyze API sets  

---

## 🆕 What's New in v1.3

✅ **API Delta Tool**: Compare two endpoint files and identify:
- 🔹 Unique endpoints in each  
- 🔁 Common/shared endpoints  
- 🤖 Fuzzy matching (e.g., `/user/123` ≈ `/user/{id}`)  

🚀 **Coming Soon**: Swagger/OpenAPI export support  

---

## ⚙️ Features

- Extracts from **Proxy History** or **Repeater**
- Optional **domain-based filtering**
- Include/exclude **HTTP methods**
- Export **full URL** or **just endpoint path**
- Normalize dynamic path segments (`/user/123` → `/user/{id}`)
- Remove **duplicate endpoints**
- Export to **CSV**, **JSON**, **Postman v2.1**
- Supports **HTTP** and **HTTPS**
- **API Delta Tool**:
  - Show unique, shared, and fuzzy-matched endpoints
  - View with a **color-coded legend**

---

## 🔧 How It Works

1. Monitors HTTP traffic from **Proxy** and **Repeater**
2. Extracts clean, parameter-free API endpoints
3. Prompts the user to configure options:
   - Source: **Proxy** or **Repeater**
   - Filter by **domain** (optional)
   - Exclude **OPTIONS**?
   - Treat HTTP methods as unique?
   - Export format: CSV, JSON, Postman v2.1
   - Full URL or just endpoint path?
   - Normalize dynamic paths?

---

## 📌 How to Use

### 🔹 To Extract Endpoints:
1. Go to **Burp** → **Extender** → **Extensions**  
2. Right-click any request in Burp  
3. Choose **"Export Unique API Endpoints"**  
4. Pick your export options  
5. Check the generated **file** for results  

### 🔹 To Use API Delta:
1. Open the **API Delta** tab  
2. Select two endpoint files (CSV)  
3. Toggle **fuzzy matching** if needed  
4. View differences via the **color-coded UI**  

---

## 📦 Requirements

- 🧪 **Burp Suite** (Community or Pro)  
- 🐍 **Jython 2.7**  
- ☕ **Java 8+**  

---

## ⚠️ Known Issues

- **Repeater requests only track after the extension is loaded**  
  ➤ *Workaround*: Group API requests into a tab and resend after loading the extension  
- **Swagger/OpenAPI export is under development**  

---
