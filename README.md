# Burp API Extractor – Unique Endpoint Exporter

Burp API Extractor is a powerful Burp Suite extension designed to extract, analyze, and export unique API endpoints from Proxy History or Repeater . It simplifies API discovery by removing unnecessary parameters, normalizing dynamic paths, and exporting results in multiple formats, including CSV , Postman (v2.1) , JSON , and Swagger/OpenAPI . The tool also introduces the API Delta feature, enabling users to compare two sets of API endpoints and identify unique and common endpoints.

## 🔹 Why Use Burp API Extractor?
- **Simplifies API discovery** by extracting clean, structured endpoints.
- **Automates filtering** based on domain, HTTP method, and dynamic path normalization.
- **Prepares API exports** in multiple formats, including **CSV, Postman (v2.1), and JSON**.
- **Enhances testing workflows** with structured data output for further analysis.

## ⚠️ Who Is It For?
Burp API Extractor is perfect for:
- **Penetration testers**: Quickly extract APIs for security testing.
- **Developers & QA teams**: Streamline API documentation and validation.
- **Bug hunters**: Identify exposed endpoints for vulnerability assessments.
- **API analysts** : Compare and analyze API datasets using the API Delta tool.

## 🔹 New in Release v1.3
- ✅  Added API Delta Tool : Compare two API endpoint datasets to identify:
Unique endpoints present in only one file.
Common endpoints shared between both files.
Fuzzy matching option to treat dynamic path parameters (e.g., {id}, {uuid}) as identical.
- 🚀 **Coming soon:** Export to **Swagger/OpenAPI** format  

## 🛠 Features
✅ Extracts endpoints from Proxy History or Repeater.
✅ Filters by domain (optional).
✅ Option to include HTTP methods or treat them as unique endpoints.
✅ Export full URL or trimmed endpoint path.
✅ Supports dynamic path normalization (e.g., /api/user/123 → /api/user/{id}).
✅ Removes duplicate endpoints.
✅ Works with both HTTP and HTTPS .
✅ Exports to CSV , Postman (v2.1) , and JSON .
✅ API Delta Tool : Compare two API endpoint datasets.
Identify unique, common, and fuzzy-matched endpoints.
Visualize results with a color-coded legend.
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

For API Delta :
1️⃣ Navigate to the API Delta tab in Burp.
2️⃣ Select two files containing API endpoints (CSV)
3️⃣ Enable fuzzy matching if needed.
4️⃣ View results with a color-coded legend

## 🛠 Requirements
- **Burp Suite** (Community or Pro)
- **Jython 2.7**
- **Java 8+**

## ⚠️ Known Issues
- **Repeater does not count old requests**: It only tracks requests **after the extension is loaded**.  
  **Workaround**: Create a **tab group** and rerun all API requests **after loading the extension**.
- **Swagger/OpenAPI export is a work in progress**.
