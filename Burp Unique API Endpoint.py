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
        path = re.sub(r'/\d+(?=/|$)', r'/\{num\}', path)

        # Replace UUIDs with {id}
        uuid_regex = r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)'
        path = re.sub(uuid_regex, r'/\{id\}', path)

        # Replace emails with {email}
        email_regex = r'/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?=/|$)'
        path = re.sub(email_regex, r'/\{email\}', path)

        return path

    def export_unique_api_endpoints(self, event):
        try:
            # Choose source
            options = ["Proxy History", "Repeater"]
            selected_option = JOptionPane.showInputDialog(None, "Select source:", "Export API URLs",
                                                          JOptionPane.QUESTION_MESSAGE, None, options, options[0])
            if not selected_option:
                self.stdout.println("No source selected. Aborting.")
                return

            # Filter by domain
            domain_filter = JOptionPane.showInputDialog("Enter domain to filter (leave blank for all):")

            # Include HTTP method?
            method_choice = JOptionPane.showConfirmDialog(None, "Include request method?", "Method Option",
                                                          JOptionPane.YES_NO_OPTION)
            include_method = (method_choice == JOptionPane.YES_OPTION)

            # Use full URL or just path?
            full_url_choice = JOptionPane.showConfirmDialog(None, "Use full URL (with domain)?", "URL Option",
                                                            JOptionPane.YES_NO_OPTION)
            use_full_url = (full_url_choice == JOptionPane.YES_OPTION)

            # Normalize endpoints?
            normalize_choice = JOptionPane.showConfirmDialog(None, "Normalize common dynamic parts (IDs, UUIDs, emails)?",
                                                             "Normalization Option", JOptionPane.YES_NO_OPTION)
            apply_normalization = (normalize_choice == JOptionPane.YES_OPTION)

            # Get source
            if selected_option == "Proxy History":
                requests = self.callbacks.getProxyHistory()
            else:
                requests = self.repeater_requests

            unique_entries = set()
            filename = "burp_unique_api_endpoints.csv"

            for item in requests:
                if not item:
                    continue

                analyzed = self.helpers.analyzeRequest(item)
                request = item.getRequest()
                url = analyzed.getUrl()

                method = analyzed.getMethod()
                path = url.getPath().split("?")[0]

                # Apply normalization
                if apply_normalization:
                    path = self.normalize_path(path)

                # Domain filter
                host = url.getHost()
                if domain_filter and domain_filter not in host:
                    continue

                # Final URL
                if use_full_url:
                    endpoint = "{}://{}{}".format(url.getProtocol(), host, path)
                else:
                    endpoint = path.lstrip("/")  # remove leading slash

                if include_method:
                    unique_entries.add((method, endpoint))
                else:
                    unique_entries.add(endpoint)

            # Export to CSV
            with open(filename, "wb") as f:
                writer = csv.writer(f)
                if include_method:
                    writer.writerow(["Method", "Endpoint"])
                    for method, endpoint in sorted(unique_entries):
                        writer.writerow([method, endpoint.encode("utf-8")])
                else:
                    writer.writerow(["Endpoint"])
                    for endpoint in sorted(unique_entries):
                        writer.writerow([endpoint.encode("utf-8")])

            self.stdout.println("✅ Exported {} unique endpoints to {}".format(len(unique_entries), filename))

        except Exception as e:
            self.stderr.println("❌ Error: {}".format(str(e)))
