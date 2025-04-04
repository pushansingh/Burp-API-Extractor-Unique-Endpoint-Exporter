# Burp API Extractor – Unique Endpoint Exporter

Burp API Extractor is a Burp Suite extension that helps export unique API endpoints from either **Proxy History** or **Repeater**. It supports **domain filtering**, **HTTP method inclusion**, **path normalization**, and the choice between **full URLs** or just **endpoint paths**. Results are exported to a **CSV file**.

## 🔹 Features
- ✅ Extracts endpoints from **Proxy History** or **Repeater**
- ✅ Filters by **domain** (optional)
- ✅ Option to include **HTTP methods**
- ✅ Option to export **full URL** or **trimmed endpoint path**
- ✅ Supports **dynamic path normalization** (e.g. `/api/user/123` → `/api/user/{num}`)
- ✅ Removes **duplicate endpoints**
- ✅ Works with both **HTTP and HTTPS**

## 🛠️ How It Works
1. **Listens** to HTTP requests in **Proxy** and **Repeater** tabs.
2. **Extracts** clean API endpoints (removes query parameters).
3. **Prompts user** to choose:
   - **Source** (Proxy or Repeater)
   - **Filter domain** (optional)
   - **Include method?** (GET/POST, etc.)
   - **Full URL** or **trimmed path?**
   - **Normalize dynamic paths?**
4. **Saves results** to `burp_unique_api_endpoints.csv`.

## 📌 How to Use
1️⃣ Install via **Burp** → **Extender** → **Extensions**  
2️⃣ Right-click any request in Burp  
3️⃣ Click Extension > **"Export Unique API Endpoints"**  
4️⃣ Choose **export options** via prompts  
5️⃣ Check generated **CSV** for results  (The generated CSV will be in the same folder as the extension)

Burp API Extractor is a Burp Suite extension to extract and export **unique, clean API endpoints** from **Proxy or Repeater**. Supports method inclusion, path normalization, domain filtering, and CSV export.

## 🛠 Requirements
- **Burp Suite** (Community or Pro)
- **Jython 2.7**
- **Java 8+**
