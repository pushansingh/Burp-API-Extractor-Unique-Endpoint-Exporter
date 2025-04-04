# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JTextField, JCheckBox, JMenuItem, JComboBox, JOptionPane, JLabel, JTextArea, JScrollPane, BorderFactory
import java.awt
import csv
import json
import re
import os
from javax.swing import GroupLayout
from java.util import LinkedHashMap
from java.net import URL

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

    def normalize_path(self, path, normalize_query):
        try:
            if not path:
                return ""
            if normalize_query:
                if not path.startswith("/"):
                    path = "/" + path
                parsed_url = URL("http://example.com" + path)
                path_only = parsed_url.getPath()
                query = parsed_url.getQuery()
                if query:
                    param_map = LinkedHashMap()
                    for pair in query.split("&"):
                        if "=" in pair:
                            k, _ = pair.split("=", 1)
                            param_map.put(k, "{var}")
                        else:
                            param_map.put(pair, "{var}")
                    norm_query = "&".join(["{}={}".format(k, param_map.get(k)) for k in param_map.keySet()])
                    return path_only + "?" + norm_query
                else:
                    return path_only
            else:
                return path
        except Exception as e:
            self.stderr.println("⚠ Error in normalize_path: {}".format(str(e)))
            return path or ""

    def normalize_tokens(self, path):
        path = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{uuid}", path)
        path = re.sub(r"[\w\.-]+@[\w\.-]+", "{email}", path)
        path = re.sub(r"(?<=/)\d+(?=/|$|\?)", "{id}", path)
        return path

    def normalize_data_tokens(self, text):
        if not text:
            return text
        text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{uuid}", text)
        text = re.sub(r"[\w\.-]+@[\w\.-]+", "{email}", text)
        text = re.sub(r"\b\d+\b", "{id}", text)
        return text

    def export_unique_api_endpoints(self, event):
        panel = JPanel()
        panel.setLayout(GroupLayout(panel))
        panel.setPreferredSize(java.awt.Dimension(600, 650))
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        layout = panel.getLayout()
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        font = java.awt.Font("Dialog", java.awt.Font.PLAIN, 14)

        source_label = JLabel("Source")
        source_label.setFont(font)
        source_options = JComboBox(["Proxy History", "Repeater"])
        source_options.setFont(font)

        domain_label = JLabel("Domain Filter (optional):")
        domain_label.setFont(font)
        domain_field = JTextField(20)
        domain_field.setFont(font)
        domain_field.setPreferredSize(java.awt.Dimension(400, 25))

        include_method_cb = JCheckBox("Include HTTP Method in Export")
        normalize_cb = JCheckBox("Normalize endpoints (path + query params)")
        full_url_cb = JCheckBox("Include full URL (with domain)")
        exclude_options_cb = JCheckBox("Exclude OPTIONS requests")
        treat_method_unique_cb = JCheckBox("Treat GET, POST, etc. as same endpoint")

        for cb in [include_method_cb, normalize_cb, full_url_cb, exclude_options_cb, treat_method_unique_cb]:
            cb.setFont(font)

        export_label = JLabel("Export Format")
        export_label.setFont(font)
        export_options = JComboBox(["CSV", "JSON", "Postman", "Swagger/OpenAPI"])
        export_options.setFont(font)

        love_art = JTextArea()
        love_art.setText(" /\_/\   \n( o.o )  \n > ^ <   ")
        love_art.setFont(java.awt.Font("Monospaced", java.awt.Font.PLAIN, 20))
        love_art.setEditable(False)
        love_art.setBackground(java.awt.Color(255, 255, 255))
        love_art.setBorder(BorderFactory.createLineBorder(java.awt.Color.LIGHT_GRAY))
        scroll_pane = JScrollPane(love_art)
        scroll_pane.setPreferredSize(java.awt.Dimension(480, 150))

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup().addComponent(source_label).addComponent(source_options))
                .addGroup(layout.createSequentialGroup().addComponent(domain_label).addComponent(domain_field))
                .addComponent(include_method_cb)
                .addComponent(normalize_cb)
                .addComponent(full_url_cb)
                .addComponent(exclude_options_cb)
                .addComponent(treat_method_unique_cb)
                .addGroup(layout.createSequentialGroup().addComponent(export_label).addComponent(export_options))
                .addComponent(scroll_pane)
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup().addComponent(source_label).addComponent(source_options))
                .addGroup(layout.createParallelGroup().addComponent(domain_label).addComponent(domain_field))
                .addComponent(include_method_cb)
                .addComponent(normalize_cb)
                .addComponent(full_url_cb)
                .addComponent(exclude_options_cb)
                .addComponent(treat_method_unique_cb)
                .addGroup(layout.createParallelGroup().addComponent(export_label).addComponent(export_options))
                .addComponent(scroll_pane)
        )

        response = JOptionPane.showConfirmDialog(None, panel, "Export Unique API Endpoints", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)

        if response != JOptionPane.OK_OPTION:
            self.stdout.println("Export canceled.")
            return

        selected_option = source_options.getSelectedItem()
        domain_filter = domain_field.getText()
        include_method = include_method_cb.isSelected()
        normalize = normalize_cb.isSelected()
        full_url = full_url_cb.isSelected()
        exclude_options = exclude_options_cb.isSelected()
        treat_same_endpoint = treat_method_unique_cb.isSelected()
        method_uniqueness = not treat_same_endpoint
        export_format = export_options.getSelectedItem()

        unique_set = {}
        postman_items = []
        method_map = {}
        filename = "burp_export." + export_format.lower()

        if selected_option == "Proxy History":
            messages = self.callbacks.getProxyHistory()
        else:
            messages = self.repeater_requests

        for item in messages:
            http_service = item.getHttpService()
            if not http_service:
                continue
            host = http_service.getHost()
            port = http_service.getPort()
            protocol = "https" if port == 443 else "http"
            request_info = self.helpers.analyzeRequest(item)

            method = request_info.getMethod()
            if exclude_options and method.upper() == "OPTIONS":
                continue

            url = request_info.getUrl()
            path = url.getPath()
            query = url.getQuery()
            raw_path = path
            if query:
                raw_path += "?" + query
            raw_path = self.normalize_path(raw_path, normalize)
            raw_path = self.normalize_tokens(raw_path)

            if full_url:
                full_url_val = protocol + "://" + host + raw_path
            else:
                full_url_val = raw_path.lstrip("/")

            if domain_filter and domain_filter not in host:
                continue

            if method_uniqueness:
                key = method.upper() + "||" + full_url_val
                if key not in unique_set:
                    unique_set[key] = method.upper()
            else:
                key = full_url_val
                if key not in method_map:
                    method_map[key] = set()
                method_map[key].add(method.upper())
                unique_set[key] = method_map[key]

            body = ""
            if method.upper() in ["POST", "PUT"]:
                raw_body = self.helpers.bytesToString(item.getRequest()[request_info.getBodyOffset():])
                body = self.normalize_data_tokens(raw_body)

            headers = request_info.getHeaders()
            header_dict = {
                h.split(":", 1)[0]: self.normalize_data_tokens(h.split(":", 1)[1])
                for h in headers[1:] if ":" in h
            }

            postman_items.append({
                "method": method.upper(),
                "url": full_url_val,
                "host": "{}://{}".format(protocol, host),
                "path": raw_path,
                "headers": header_dict,
                "body": body
            })

        try:
            if export_format == "CSV":
                with open(filename, "w") as f:
                    writer = csv.writer(f)
                    if include_method:
                        writer.writerow(["Method", "Endpoint"])
                        for k, v in sorted(unique_set.items()):
                            if isinstance(v, set):
                                writer.writerow(["|".join(sorted(v)), k])
                            else:
                                endpoint = k.split("||", 1)[-1].strip()
                                writer.writerow([v.strip(), endpoint])
                    else:
                        writer.writerow(["Endpoint"])
                        seen = set()
                        for k in unique_set:
                            ep = k.split("||", 1)[-1].strip()
                            if ep not in seen:
                                writer.writerow([ep])
                                seen.add(ep)

            elif export_format == "JSON":
                json.dump(list(unique_set.keys()), open(filename, "w"), indent=2)

            elif export_format == "Postman":
                postman_export = {
                    "info": {
                        "name": "Burp Export",
                        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                    },
                    "item": []
                }
                for item in postman_items:
                    postman_export["item"].append({
                        "name": item["path"],
                        "request": {
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
                    })
                json.dump(postman_export, open(filename, "w"), indent=2)

            elif export_format == "Swagger/OpenAPI":
                paths = {}
                for item in postman_items:
                    clean_path = "/" + re.sub(r"https?://[^/]+", "", item["url"]).split("?")[0].lstrip("/")
                    if clean_path not in paths:
                        paths[clean_path] = {}
                    paths[clean_path][item["method"].lower()] = {
                        "responses": {"200": {"description": "Success"}}
                    }
                swagger = {
                    "openapi": "3.0.0",
                    "info": {"title": "Burp Export", "version": "1.0.0"},
                    "paths": paths
                }
                json.dump(swagger, open(filename, "w"), indent=2)

            self.stdout.println("\u2714 Exported to: {}".format(filename))

        except Exception as e:
            self.stderr.println("\u2716 Error: {}".format(str(e)))
