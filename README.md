# Burp-API-Extractor-Unique-Endpoint-Exporter
Burp API Extractor is a Burp Suite extension that helps export unique API endpoints from either Proxy History or Repeater requests. It allows filtering by domain and saves the extracted endpoints to a CSV file.
📝 Extension Description
Burp API Extractor is a Burp Suite extension that helps export unique API endpoints from either Proxy History or Repeater requests. It allows filtering by domain and saves the extracted endpoints to a CSV file.

🔹 Features:
✅ Extracts API endpoints from Proxy History and Repeater requests
✅ Filters requests by domain (optional)
✅ Removes duplicate endpoints
✅ Saves clean API paths (excluding query parameters)
✅ Works with HTTPS & HTTP requests

🛠️ How It Works
The extension listens for HTTP requests in Burp Suite’s Proxy History and Repeater tabs.

It extracts only the API endpoints (ignoring request methods & parameters).

Users can choose to export from Proxy History or Repeater requests.

(Optional) Users can filter by domain to export APIs from a specific host.

The results are saved in a CSV file (burp_unique_api_endpoints.csv).

📌 How to Use
1️⃣ Install the extension in Burp Suite → Extender → Extensions
2️⃣ Right-click inside Burp (any request in History or Repeater)
3️⃣ Click "Export Unique API Endpoints"
4️⃣ Select the source (Proxy History or Repeater)
5️⃣ (Optional) Enter a domain to filter requests
6️⃣ The CSV file is generated with all unique API endpoints

📂 GitHub Repository Description
Burp API Extractor – Unique Endpoint Exporter
This Burp Suite extension extracts unique API endpoints from either Proxy History or Repeater requests and saves them to a CSV file. It also allows filtering by domain and removes duplicates.

🛠 Requirements
Burp Suite (Community or Pro)

Jython 2.7 (for running Python extensions in Burp)

Java 8 or later (since Burp requires Java)

💾 Installation
Install Jython in Burp Suite

Go to Burp Suite → Extender → Options

Under Python Environment, select the Jython standalone .jar

Load the Extension

Go to Burp Suite → Extender → Extensions → Add

Select the Python file containing the script

Export APIs

Right-click anywhere in Burp Suite

Select "Export Unique API Endpoints"

Choose Proxy History or Repeater

(Optional) Enter a domain filter

Check burp_unique_api_endpoints.csv for the exported APIs 🎯

