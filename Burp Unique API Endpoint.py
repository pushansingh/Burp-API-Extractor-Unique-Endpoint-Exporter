# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import PrintWriter
from javax.swing import JMenuItem, JOptionPane
import csv
import re

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.repeater_requests = []

        callbacks.setExtensionName("Export Unique API Endpoints")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self.callbacks.TOOL_REPEATER and messageIsRequest:
            self.repeater_requests.append(messageInfo)

    def createMenuItems(self, invocation):
        menu = JMenuItem("Export Unique API Endpoints", actionPerformed=self.export_unique_api_endpoints)
        return [menu]

    def normalize_path(self, path):
        # Replace numbers with {num}
        path = re.sub(r'/\d+([/?])?', r'/\{num\}\1', path)

        # Replace UUIDs with {id}
        uuid_regex = r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        path = re.sub(uuid_regex, r'/\{id\}', path)

        return path

    def export_unique_api_endpoints(self, event):
        try:
            # Source prompt
            options = ["Proxy History", "Repeater"]
            selected_option = JOptionPane.showInputDialog(None, "Select source:", "Export API URLs",
                                                          JOptionPane.QUESTION_MESSAGE, None, options, options[0])
            if not selected_option:
                self.stdout.println("No option selected. Aborting.")
                return

            # Domain filter
            domain_filter = JOptionPane.showInputDialog("Enter domain to filter (leave blank for all):")
            domain_filter = domain_filter.strip() if domain_filter else ""

            # Include method
            method_choice = JOptionPane.showConfirmDialog(None, "Do you want to include request method?",
                                                          "Method Column", JOptionPane.YES_NO_OPTION)
            include_method = (method_choice == JOptionPane.YES_OPTION)

            # Use full URL or just path
            full_url_choice = JOptionPane.showConfirmDialog(None, "Do you want full URL (with domain)?",
                                                            "URL Format", JOptionPane.YES_NO_OPTION)
            use_full_url = (full_url_choice == JOptionPane.YES_OPTION)

            # Normalize dynamic values
            normalize_choice = JOptionPane.showConfirmDialog(None, "Do you want to normalize dynamic segments (IDs, numbers)?",
                                                             "Normalize Endpoints", JOptionPane.YES_NO_OPTION)
            normalize_dynamic = (normalize_choice == JOptionPane.YES_OPTION)

            # Collect requests
            if selected_option == "Proxy History":
                requests = self.callbacks.getProxyHistory()
            else:
                requests = self.repeater_requests

            unique_entries = set()

            for item in requests:
                http_service = item.getHttpService()
                if not http_service:
                    continue

                host = http_service.getHost()
                port = http_service.getPort()
                protocol = "https" if port == 443 else "http"

                request_info = self.helpers.analyzeRequest(item)
                method = request_info.getMethod()
                url = request_info.getUrl()
                path = url.getPath().split("?")[0]  # Remove query params

                # Domain filter
                if domain_filter and domain_filter not in host:
                    continue

                # Normalize if required
                if normalize_dynamic:
                    path = self.normalize_path(path)

                if use_full_url:
                    endpoint = "{}://{}{}".format(protocol, host, path)
                else:
                    endpoint = path.lstrip("/")

                if include_method:
                    unique_entries.add((method, endpoint))
                else:
                    unique_entries.add(endpoint)

            filename = "burp_unique_api_endpoints.csv"

            # Write CSV (Jython-friendly)
            f = open(filename, "wb")
            writer = csv.writer(f)
            if include_method:
                writer.writerow(["Method", "Endpoint"])
                for method, endpoint in sorted(unique_entries):
                    writer.writerow([method, endpoint.encode("utf-8")])
            else:
                writer.writerow(["Endpoint"])
                for endpoint in sorted(unique_entries):
                    writer.writerow([endpoint.encode("utf-8")])
            f.close()

            self.stdout.println("✅ Unique API endpoints exported to '{}'".format(filename))

        except Exception as e:
            self.stderr.println("❌ Error: {}".format(str(e)))
