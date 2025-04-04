# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JTextField, JCheckBox, JMenuItem, JComboBox, JOptionPane, JLabel, JTextArea, JScrollPane
import java.awt  # Make sure to import this for Dimension
import csv
import json
import re
import os
from javax.swing import GroupLayout

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

    def normalize_path(self, path, normalize):
        if normalize:
            path = re.sub(r"/\d+(?=/|$)", "/{num}", path)
            path = re.sub(r"/[a-fA-F0-9-]{36}(?=/|$)", "/{uuid}", path)
            path = re.sub(r"/[^/]+@[^/]+(?=/|$)", "/{email}", path)
        return path

    def export_unique_api_endpoints(self, event):
        # Create a panel with all the options
        panel = JPanel()
        panel.setLayout(GroupLayout(panel))  # Using GroupLayout for better resizing
        panel.setPreferredSize(java.awt.Dimension(600, 650))  # Set initial preferred size

        group_layout = panel.getLayout()
        group_layout.setAutoCreateGaps(True)
        group_layout.setAutoCreateContainerGaps(True)

        # Select Source: Proxy History or Repeater (Non-editable)
        source_label = JLabel("Select Source (Proxy History or Repeater)")
        source_options = JComboBox(["Proxy History", "Repeater"])
        source_options.setEditable(False)

        # Domain Filter (Non-editable Label with Editable TextField below)
        domain_label = JLabel("Enter domain to filter (leave blank for all):")
        domain_field = JTextField()
        domain_field.setColumns(20)  # Set the number of visible columns for the text field

        # Method Column
        method_label = JCheckBox("Include Request Method")

        # Full URL Option
        full_url_label = JCheckBox("Include Full URL (with domain)")

        # Normalize Endpoints Option
        normalize_label = JCheckBox("Normalize Endpoints (e.g., numbers, UUIDs)")

        # Exclude OPTIONS Requests
        exclude_options_label = JCheckBox("Exclude OPTIONS Requests")

        # Treat Different Methods as Unique
        treat_method_as_unique = JCheckBox("Treat Different Methods for Same Endpoint as Unique")

        # Export Format
        export_label = JLabel("Select Export Format (CSV, JSON, Postman, Swagger/OpenAPI)")
        export_options = JComboBox(["CSV", "JSON", "Postman", "Swagger/OpenAPI"])
        export_options.setEditable(False)

        # Watermark: ASCII Art as non-editable text (using JTextArea)
        love_art = JTextArea()
        love_art.setText(
            " /\_/\   \n"
            "( o.o )  \n"
            " > ^ <   \n"
        )
        love_art.setFont(java.awt.Font("Monospaced", java.awt.Font.PLAIN, 20))  # Increased font size for large art
        love_art.setEditable(False)  # Non-editable
        love_art.setBackground(java.awt.Color(255, 255, 255))  # Make the background white
        love_art.setCaretPosition(0)  # Ensure text starts from top
        love_art.setAlignmentX(JTextArea.CENTER_ALIGNMENT)  # Center the ASCII Art

        # Add a JScrollPane to make it scrollable if necessary
        scroll_pane = JScrollPane(love_art)
        scroll_pane.setPreferredSize(java.awt.Dimension(480, 150))  # Adjusted size for scrollable area

        # Layout configuration using GroupLayout
        layout = panel.getLayout()
        h_group = layout.createParallelGroup(GroupLayout.Alignment.LEADING)
        v_group = layout.createSequentialGroup()

        # Add components in the appropriate groups for layout management
        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(source_label)
            .addComponent(source_options))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(domain_label)
            .addComponent(domain_field))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(method_label))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(full_url_label))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(normalize_label))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(exclude_options_label))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(treat_method_as_unique))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(export_label)
            .addComponent(export_options))

        h_group.addGroup(layout.createSequentialGroup()
            .addComponent(scroll_pane))

        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(source_label)
            .addComponent(source_options))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(domain_label)
            .addComponent(domain_field))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(method_label))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(full_url_label))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(normalize_label))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(exclude_options_label))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(treat_method_as_unique))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(export_label)
            .addComponent(export_options))
        v_group.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(scroll_pane))

        layout.setHorizontalGroup(h_group)
        layout.setVerticalGroup(v_group)

        # Show the panel with all the options
        response = JOptionPane.showConfirmDialog(None, panel, "Export Unique API Endpoints", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)

        if response != JOptionPane.OK_OPTION:
            self.stdout.println("User canceled the export. Aborting.")
            return

        selected_option = source_options.getSelectedItem()
        domain_filter = domain_field.getText()
        include_method = method_label.isSelected()
        use_full_url = full_url_label.isSelected()
        normalize = normalize_label.isSelected()
        exclude_options_flag = exclude_options_label.isSelected()
        treat_methods_as_unique = treat_method_as_unique.isSelected()
        export_format = export_options.getSelectedItem()

        filename = "burp_unique_api_export.{}".format(export_format.lower())
        unique_entries = set()
        postman_items = []

        try:
            requests = []
            if selected_option == "Proxy History":
                requests = self.callbacks.getProxyHistory()
            elif selected_option == "Repeater":
                requests = self.repeater_requests

            for item in requests:
                http_service = item.getHttpService()
                if not http_service:
                    continue

                host = http_service.getHost()
                port = http_service.getPort()
                protocol = "https" if port == 443 else "http"

                request_info = self.helpers.analyzeRequest(item)
                headers = request_info.getHeaders()
                method = request_info.getMethod()
                if exclude_options_flag and method.upper() == "OPTIONS":
                    continue

                url = request_info.getUrl()
                path = url.getPath()
                query = url.getQuery()
                if query:
                    path += "?" + query

                path = self.normalize_path(path, normalize)

                if use_full_url:
                    full_url = "{}://{}{}".format(protocol, host, path)
                else:
                    full_url = path.lstrip("/")

                if domain_filter and domain_filter not in host:
                    continue

                if include_method:
                    entry = (method.upper(), full_url)
                else:
                    entry = full_url

                # If treating methods as unique, add method to the key
                if treat_methods_as_unique or entry not in unique_entries:
                    unique_entries.add(entry)

                    if export_format in ["Postman", "Swagger/OpenAPI"]:
                        header_dict = {h.split(":", 1)[0].strip(): h.split(":", 1)[1].strip() for h in headers[1:] if ":" in h}
                        body = ""
                        if method.upper() in ["POST", "PUT"]:
                            body = self.helpers.bytesToString(item.getRequest()[request_info.getBodyOffset():])

                        postman_items.append({
                            "method": method.upper(),
                            "url": full_url,
                            "host": "{}://{}".format(protocol, host),
                            "path": path,
                            "headers": header_dict,
                            "body": body
                        })

            if export_format == "CSV":
                with open(filename, "wb") as f:
                    writer = csv.writer(f)
                    if include_method:
                        writer.writerow(["Method", "Endpoint"])
                        for method, endpoint in sorted(unique_entries):
                            writer.writerow([method, endpoint])
                    else:
                        writer.writerow(["Endpoint"])
                        for endpoint in sorted(unique_entries):
                            writer.writerow([endpoint])

            elif export_format == "JSON":
                with open(filename, "w") as f:
                    json.dump(sorted(list(unique_entries)), f, indent=2, ensure_ascii=False)

            elif export_format == "Postman":
                postman_export = {
                    "info": {
                        "name": "Burp Export",
                        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                    },
                    "item": []
                }
                for item in postman_items:
                    request_obj = {
                        "method": item["method"],
                        "header": [{"key": k, "value": v} for k, v in item["headers"].items()],
                        "url": {
                            "raw": item["url"],
                            "host": [item["host"].split("://")[1]],
                            "path": item["path"].strip("/").split("/")
                        },
                        "body": {
                            "mode": "raw",
                            "raw": item["body"]
                        }
                    }
                    postman_export["item"].append({
                        "name": item["path"],
                        "request": request_obj
                    })
                with open(filename, "w") as f:
                    json.dump(postman_export, f, indent=2, ensure_ascii=False)

            elif export_format == "Swagger/OpenAPI":
                paths = {}
                for item in postman_items:
                    clean_path = "/" + re.sub(r"https?://[^/]+", "", item["url"]).split("?")[0].lstrip("/")
                    if clean_path not in paths:
                        paths[clean_path] = {}
                    paths[clean_path][item["method"].lower()] = {
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    }
                swagger = {
                    "openapi": "3.0.0",
                    "info": {
                        "title": "Burp Export",
                        "version": "1.0.0"
                    },
                    "paths": paths
                }
                with open(filename, "w") as f:
                    json.dump(swagger, f, indent=2, ensure_ascii=False)

            self.stdout.println("\u2714 Exported to: {}".format(filename))

        except Exception as e:
            self.stderr.println("\u2716 Error: {}".format(str(e)))
