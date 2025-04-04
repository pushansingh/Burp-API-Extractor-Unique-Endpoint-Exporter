# Burp API Extractor – Unique Endpoint Exporter

Burp API Extractor is a Burp Suite extension designed to **extract and export unique API endpoints** from **Proxy History** or **Repeater**. It offers **domain filtering**, **HTTP method inclusion**, **path normalization**, and now supports **Postman collection format (v2.1)** and **JSON export**. Results can be saved in **CSV**, **Postman**, or **JSON** formats.

## 🔹 New in Release v1.2
- ✅ General **usability polish** and **minor UI enhancements**  
- ✅ Added **export to Postman (v2.1 collection format)** and **JSON**  
- ✅ New **checkbox to exclude OPTIONS requests** from export  
- ✅ New **checkbox to treat different HTTP methods (GET/POST/etc.) as unique endpoints**  
- 🚀 **Coming soon:** Export to **Swagger/OpenAPI** format  

## 🛠 Features
- ✅ Extracts endpoints from **Proxy History** or **Repeater**
- ✅ Filters by **domain** (optional)
- ✅ Option to **include HTTP methods** or treat them as **unique endpoints**
- ✅ Option to export **full URL** or **trimmed endpoint path**
- ✅ Supports **dynamic path normalization** (e.g., `/api/user/123` → `/api/user/{num}`)
- ✅ **Removes duplicate endpoints**
- ✅ Works with both **HTTP and HTTPS**
- ✅ Exports to **CSV, Postman (v2.1), and JSON**  
- 🚀 **Upcoming:** Swagger/OpenAPI support  

## 🛠️ How It Works
1. **Listens** to HTTP requests in **Proxy** and **Repeater** tabs.
2. **Extracts** clean API endpoints (removes query parameters).
3. **Prompts user** to choose:
   - **Source** (Proxy or Repeater)
   - **Filter domain** (optional)
   - **Exclude OPTIONS requests?**
   - **Treat HTTP methods as unique endpoints?**
   - **Export format:** CSV, JSON, or Postman (v2.1)
   - **Full URL** or **trimmed path?**
   - **Normalize dynamic paths?**

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


## ⚠️ Known Issues
- **Repeater does not count old requests**: It only tracks requests **after the extension is loaded**.  
  **Workaround**: Create a **tab group** and rerun all API requests **after loading the extension**.
- **Postman collection export does not append `http` or `https`** to requests.  
- **Swagger/OpenAPI export is a work in progress**.
