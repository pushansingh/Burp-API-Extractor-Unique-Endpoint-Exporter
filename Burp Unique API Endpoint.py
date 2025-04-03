# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import PrintWriter
from javax.swing import JMenuItem, JOptionPane
import csv

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        self.repeater_requests = []  # Store Repeater requests
        
        callbacks.setExtensionName("Export Unique API Endpoints")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)  # Listen for HTTP requests

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Capture Repeater requests dynamically
        if toolFlag == self.callbacks.TOOL_REPEATER and messageIsRequest:
            self.repeater_requests.append(messageInfo)

    def createMenuItems(self, invocation):
        menu = JMenuItem("Export Unique API Endpoints", actionPerformed=self.export_unique_api_endpoints)
        return [menu]

    def export_unique_api_endpoints(self, event):
        # Ask user where to extract requests from
        options = ["Proxy History", "Repeater"]
        selected_option = JOptionPane.showInputDialog(None, "Select source:", "Export API URLs", 
                                                      JOptionPane.QUESTION_MESSAGE, None, options, options[0])

        if not selected_option:
            self.stdout.println("No option selected. Aborting export.")
            return

        # Ask user for domain filter (optional)
        domain_filter = JOptionPane.showInputDialog("Enter domain to filter (leave blank for all):")

        filename = "burp_unique_api_endpoints.csv"
        unique_endpoints = set()

        try:
            if selected_option == "Proxy History":
                requests = self.callbacks.getProxyHistory()  # Fetch all history requests
            elif selected_option == "Repeater":
                requests = self.repeater_requests  # Get stored Repeater requests

            for item in requests:
                http_service = item.getHttpService()
                if not http_service:
                    continue

                host = http_service.getHost()
                port = http_service.getPort()
                protocol = "https" if port == 443 else "http"

                # Get request details
                request_info = self.helpers.analyzeRequest(item)
                url = "{}://{}{}".format(protocol, host, request_info.getUrl().getPath())

                # Apply domain filter if provided
                if domain_filter and domain_filter not in host:
                    continue  # Skip non-matching URLs

                # Extract only the endpoint (removing query params)
                endpoint = url.split("?")[0]

                unique_endpoints.add(endpoint)

            # Save to CSV
            with open(filename, "wb") as csvfile:  # Jython-compatible
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(["Endpoint"])

                for endpoint in sorted(unique_endpoints):
                    csv_writer.writerow([endpoint.encode('utf-8')])

            self.stdout.println("Unique API endpoints exported to {}".format(filename))

        except Exception as e:
            self.stderr.println("Error: {}".format(str(e)))
