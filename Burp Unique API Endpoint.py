# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener, ITab
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JTextField, JCheckBox, JMenuItem, JComboBox, JOptionPane, JLabel, JTextArea, JScrollPane, BorderFactory, JFileChooser
import java.awt
import csv
import json
import re
import os
import time
from javax.swing import GroupLayout
from java.util import LinkedHashMap
from java.net import URL
from javax.swing import JTextPane
from java.lang import Runnable, Thread
from java.util import UUID
from javax.swing.text import DefaultHighlighter, StyleConstants
from javax.swing.text import SimpleAttributeSet, StyleContext
from java.awt import Color

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.repeater_requests = []
        self.main_panel = None

        callbacks.setExtensionName("Export Unique API Endpoints")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        self.create_delta_tab()
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "API Delta"

    def getUiComponent(self):
        return self.main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self.callbacks.TOOL_REPEATER and messageIsRequest:
            if messageInfo not in self.repeater_requests:
                self.repeater_requests.append(messageInfo)

    def createMenuItems(self, invocation):
        menu = JMenuItem("Export Unique API Endpoints", actionPerformed=self.show_export_dialog)
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

    def show_export_dialog(self, event):
        panel = JPanel()
        panel.setLayout(GroupLayout(panel))
        panel.setPreferredSize(java.awt.Dimension(600, 650))
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))
        layout = panel.getLayout()
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        font = java.awt.Font("Dialog", java.awt.Font.PLAIN, 14)

        export_label = JLabel("Export Format")
        export_label.setFont(font)
        export_options = JComboBox(["CSV", "JSON", "Postman", "Swagger/OpenAPI"])
        export_options.setFont(font)

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

        all_checkboxes = [
            include_method_cb,
            normalize_cb,
            full_url_cb,
            exclude_options_cb,
            treat_method_unique_cb
        ]

        for cb in all_checkboxes:
            cb.setFont(font)

        love_art = JTextArea()
        love_art.setText(" /\_/\   \n( o.o )  \n > ^ <   ")
        love_art.setFont(java.awt.Font("Monospaced", java.awt.Font.PLAIN, 20))
        love_art.setEditable(False)
        love_art.setBackground(java.awt.Color(255, 255, 255))
        love_art.setBorder(BorderFactory.createLineBorder(java.awt.Color.LIGHT_GRAY))
        scroll_pane = JScrollPane(love_art)
        scroll_pane.setPreferredSize(java.awt.Dimension(480, 150))

        def toggleCheckboxesForFormat(format_val):
            show = {
                "Include HTTP Method in Export": format_val == "CSV",
                "Normalize endpoints (path + query params)": True,
                "Include full URL (with domain)": format_val != "Swagger/OpenAPI",
                "Exclude OPTIONS requests": True,
                "Treat GET, POST, etc. as same endpoint": True
            }
            for cb in all_checkboxes:
                cb.setVisible(show[cb.getText()])

        toggleCheckboxesForFormat(export_options.getSelectedItem())
        export_options.addItemListener(lambda e: toggleCheckboxesForFormat(export_options.getSelectedItem()))

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup().addComponent(export_label).addComponent(export_options))
                .addGroup(layout.createSequentialGroup().addComponent(source_label).addComponent(source_options))
                .addGroup(layout.createSequentialGroup().addComponent(domain_label).addComponent(domain_field))
                .addComponent(include_method_cb)
                .addComponent(normalize_cb)
                .addComponent(full_url_cb)
                .addComponent(exclude_options_cb)
                .addComponent(treat_method_unique_cb)
                .addComponent(scroll_pane)
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup().addComponent(export_label).addComponent(export_options))
                .addGroup(layout.createParallelGroup().addComponent(source_label).addComponent(source_options))
                .addGroup(layout.createParallelGroup().addComponent(domain_label).addComponent(domain_field))
                .addComponent(include_method_cb)
                .addComponent(normalize_cb)
                .addComponent(full_url_cb)
                .addComponent(exclude_options_cb)
                .addComponent(treat_method_unique_cb)
                .addComponent(scroll_pane)
        )

        try:
            burp_frame = self.callbacks.getBurpFrame()
        except AttributeError:
            burp_frame = None

        response = JOptionPane.showConfirmDialog(burp_frame, panel, "Export Unique API Endpoints", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)

        if response != JOptionPane.OK_OPTION:
            self.stdout.println("Export canceled.")
            return

        config = {
            "export_format": export_options.getSelectedItem(),
            "source_option": source_options.getSelectedItem(),
            "domain_filter": domain_field.getText(),
            "include_method": include_method_cb.isVisible() and include_method_cb.isSelected(),
            "normalize": normalize_cb.isSelected(),
            "full_url": full_url_cb.isVisible() and full_url_cb.isSelected(),
            "exclude_options": exclude_options_cb.isSelected(),
            "method_uniqueness": not treat_method_unique_cb.isSelected()
        }

        class ExportTask(Runnable):
            def run(self):
                try:
                    self.do_export(config)
                except Exception as e:
                    self.stderr.println("⚠ Error in export thread: {}".format(str(e)))

            def __init__(self, outer):
                self.do_export = outer.do_export
                self.stderr = outer.stderr

        Thread(ExportTask(self)).start()

    def do_export(self, config):
        export_format = config["export_format"]
        source_option = config["source_option"]
        domain_filter = config["domain_filter"]
        include_method = config["include_method"]
        normalize = config["normalize"]
        full_url = config["full_url"]
        exclude_options = config["exclude_options"]
        method_uniqueness = config["method_uniqueness"]

        base_filename = "burp_export_{}".format(int(time.time()))
        if export_format == "Postman":
            filename = base_filename + ".postman"
        elif export_format == "JSON":
            filename = base_filename + ".json"
        elif export_format == "CSV":
            filename = base_filename + ".csv"
        else:
            filename = base_filename + ".txt"

        messages = self.callbacks.getProxyHistory() if source_option == "Proxy History" else self.repeater_requests

        unique_set = {}
        postman_items = []
        method_map = {}

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
            raw_path = path + ("?" + query if query else "")

            if normalize:
                raw_path = self.normalize_path(raw_path, True)
                raw_path = self.normalize_tokens(raw_path)

            full_url_val = protocol + "://" + host + raw_path if full_url else raw_path

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
                body = self.normalize_data_tokens(raw_body) if normalize else raw_body

            headers = request_info.getHeaders()
            header_dict = {
                h.split(":", 1)[0]: h.split(":", 1)[1].strip()
                for h in headers[1:] if ":" in h
            }

            postman_items.append({
                "method": method.upper(),
                "url": full_url_val,
                "host": host,
                "protocol": protocol,
                "path": raw_path,
                "headers": header_dict,
                "body": body
            })

        try:
            with open(filename, "w") as f:
                if export_format == "CSV":
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
                    json.dump(list(unique_set.keys()), f, indent=2)

                elif export_format == "Postman":
                    postman_export = {
                        "info": {
                            "name": "Burp Export",
                            "_postman_id": str(UUID.randomUUID()),
                            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                        },
                        "item": []
                    }
                    for item in postman_items:
                        try:
                            url_obj = URL(item["url"])
                            host_parts = url_obj.getHost().split(".")
                            path_parts = [p for p in url_obj.getPath().strip("/").split("/") if p]
                            query_parts = []
                            if url_obj.getQuery():
                                for pair in url_obj.getQuery().split("&"):
                                    if "=" in pair:
                                        k, v = pair.split("=", 1)
                                        query_parts.append({"key": k, "value": v})
                                    else:
                                        query_parts.append({"key": pair, "value": ""})

                            postman_url = {
                                "raw": item["url"],
                                "protocol": item["protocol"],
                                "host": host_parts,
                                "path": path_parts
                            }
                            if query_parts:
                                postman_url["query"] = query_parts

                            postman_export["item"].append({
                                "name": item["path"],
                                "request": {
                                    "method": item["method"],
                                    "header": [{"key": k, "value": v} for k, v in item["headers"].items()],
                                    "url": postman_url,
                                    "body": {
                                        "mode": "raw",
                                        "raw": item["body"]
                                    }
                                },
                                "response": []
                            })
                        except Exception as e:
                            self.stderr.println("⚠ Error processing Postman item: {}".format(str(e)))
                            continue

                    json.dump(postman_export, f, indent=2)

                elif export_format == "Swagger/OpenAPI":
                    paths = {}
                    for item in postman_items:
                        clean_path = "/" + re.sub(r"https?://[^/]+", "", item["url"]).split("?")[0].lstrip("/")
                        if clean_path not in paths:
                            paths[clean_path] = {}
                        paths[clean_path][item["method"].lower()] = {
                            "responses": {
                                "200": {
                                    "description": "Successful response"
                                }
                            }
                        }
                    openapi = {
                        "openapi": "3.1.0",
                        "info": {
                            "title": "Burp Export",
                            "version": "1.0.0"
                        },
                        "paths": paths
                    }
                    json.dump(openapi, f, indent=2)

            os.chmod(filename, 0o644)
            self.stdout.println("✔ Exported {} items to: {}".format(len(postman_items), filename))

        except Exception as e:
            self.stderr.println("✖ Error during export: {}".format(str(e)))

    def create_delta_tab(self):
        panel = JPanel()
        panel.setLayout(GroupLayout(panel))
        layout = panel.getLayout()
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
	
	search_label = JLabel("Search:")
	search_field = JTextField(40)
	search_button = JButton("Search", actionPerformed=lambda e: perform_search())
    

        file1_button = JButton("Select File 1")
        file2_button = JButton("Select File 2")
        common_button = JButton("Show Common")
        unique_button = JButton("Show Unique")
        export_button = JButton("Export Results")
        fuzzy_match_cb = JCheckBox("Fuzzy Matching (treat path params as same)")
        
        result_area = JTextPane()
        result_area.setEditable(False)
        scroll = JScrollPane(result_area)

        file1_path = JTextField(40)
        file2_path = JTextField(40)
        file1_path.setEditable(False)
        file2_path.setEditable(False)

        def perform_search():
    		query = search_field.getText().strip().lower()
    		if not query:
        		return
   		 # Get the current text in the result area
    		current_text = result_area.getText().lower()
		highlighter = result_area.getHighlighter()
		highlighter.removeAllHighlights()
    		painter = DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW)
    		
		start = 0
    		while True:
        		start = current_text.find(query, start)
        		if start == -1:
            			break
        		end = start + len(query)
        		try:
            			highlighter.addHighlight(start, end, painter)
        		except Exception as e:
            	                self.stderr.println("⚠ Error highlighting search results: {}".format(str(e)))
        		start = end

	# Improved colors for better visibility and accessibility
        self.color_file1 = Color(255, 150, 150)  
        self.color_file2 = Color(150, 255, 150)  
        self.color_common = Color(150, 200, 255) 
        self.color_summary = Color(0, 0, 0)           
        # Create color legend panel
        legend_panel = JPanel()
        legend_panel.setLayout(java.awt.GridLayout(1, 4))
        legend_panel.setBorder(BorderFactory.createTitledBorder("Color Guide"))
        
        def create_legend_item(color, text):
            panel = JPanel()
            panel.setLayout(java.awt.BorderLayout())
            color_box = JPanel()
            color_box.setBackground(color)
            color_box.setPreferredSize(java.awt.Dimension(20, 20))
            color_box.setBorder(BorderFactory.createLineBorder(Color.BLACK))
            panel.add(color_box, java.awt.BorderLayout.WEST)
            label = JLabel(text)
            label.setFont(java.awt.Font("Dialog", java.awt.Font.PLAIN, 12))
            panel.add(label, java.awt.BorderLayout.CENTER)
            return panel
        
        legend_panel.add(create_legend_item(self.color_file1, "Unique to File 1"))
        legend_panel.add(create_legend_item(self.color_file2, "Unique to File 2"))
        legend_panel.add(create_legend_item(self.color_common, "Common to Both"))
        legend_panel.add(create_legend_item(Color.WHITE, "Other text"))

        def choose_file(field):
            chooser = JFileChooser()
            ret = chooser.showOpenDialog(panel)
            if ret == JFileChooser.APPROVE_OPTION:
                field.setText(chooser.getSelectedFile().getAbsolutePath())

        file1_button.addActionListener(lambda e: choose_file(file1_path))
        file2_button.addActionListener(lambda e: choose_file(file2_path))

        def normalize_endpoint(endpoint, fuzzy):
            if fuzzy:
                # Normalize path parameters like {id}, {email}, etc. to {param}
                endpoint = re.sub(r'\{[^}]+\}', '{param}', endpoint)
                # Also normalize numbers in paths
                endpoint = re.sub(r'(?<=/)\d+(?=/|$)', '{id}', endpoint)
            return endpoint

        def load_csv_endpoints(path, fuzzy):
            endpoints = set()
            try:
                with open(path, "r") as f:
                    reader = csv.reader(f)
                    headers = next(reader)
                    endpoint_col = headers.index("Endpoint") if "Endpoint" in headers else -1
                    method_col = headers.index("Method") if "Method" in headers else -1
                    for row in reader:
                        if endpoint_col != -1 and method_col != -1:
                            endpoint = row[endpoint_col]
                            endpoint = normalize_endpoint(endpoint, fuzzy)
                            endpoints.add(row[method_col] + " " + endpoint)
                        elif endpoint_col != -1:
                            endpoint = row[endpoint_col]
                            endpoint = normalize_endpoint(endpoint, fuzzy)
                            endpoints.add(endpoint)
            except Exception as e:
                self.stderr.println("⚠ Failed to read {}: {}".format(path, e))
            return endpoints

        def highlight_text(text, color):
            doc = result_area.getDocument()
            style = StyleContext.getDefaultStyleContext().addAttribute(SimpleAttributeSet.EMPTY, StyleConstants.Foreground, color)
            result_area.setCaretPosition(0)
            result_area.setCharacterAttributes(style, False)
            result_area.setText(text)

        def color_highlight_results(results, file1_set, file2_set, fuzzy):
            # Clear the result area
            result_area.setText("")
            
            # Get the styled document for the result area
            doc = result_area.getStyledDocument()
            
            # Create styles for coloring
            style_file1 = doc.addStyle("file1", None)
            StyleConstants.setForeground(style_file1, self.color_file1)
            StyleConstants.setBold(style_file1, True)

            style_file2 = doc.addStyle("file2", None)
            StyleConstants.setForeground(style_file2, self.color_file2)
            StyleConstants.setBold(style_file2, True)

            style_common = doc.addStyle("common", None)
            StyleConstants.setForeground(style_common, self.color_common)
            StyleConstants.setBold(style_common, True)

            style_summary = doc.addStyle("summary", None)
            StyleConstants.setForeground(style_summary, self.color_summary)
            StyleConstants.setBold(style_summary, True)

            # Count statistics
            unique_file1 = 0
            unique_file2 = 0
            common = 0

            # Add summary at the top
            summary = "Comparison Results:\n"
            summary += "Unique to File 1: {}\n".format(len(file1_set - file2_set))
            summary += "Unique to File 2: {}\n".format(len(file2_set - file1_set))
            summary += "Common endpoints: {}\n\n".format(len(file1_set & file2_set))
            
            try:
                # Insert the summary with the summary style
                doc.insertString(doc.getLength(), summary, style_summary)
            except Exception as e:
                self.stderr.println("⚠ Error inserting summary: {}".format(str(e)))

            # Process each line of the results
            for line in results.split("\n"):
                if not line.strip():
                    continue  # Skip empty lines

                # Normalize the endpoint for comparison
                endpoint = line.split(" ", 1)[-1] if " " in line else line
                endpoint = normalize_endpoint(endpoint, fuzzy)

                # Check if the endpoint belongs to File 1, File 2, or both
                in_file1 = any(normalize_endpoint(e.split(" ", 1)[-1] if " " in e else e, fuzzy) == endpoint for e in file1_set)
                in_file2 = any(normalize_endpoint(e.split(" ", 1)[-1] if " " in e else e, fuzzy) == endpoint for e in file2_set)

                # Determine the style based on the endpoint's presence
                if in_file1 and in_file2:
                    style = style_common
                    common += 1
                elif in_file1:
                    style = style_file1
                    unique_file1 += 1
                elif in_file2:
                    style = style_file2
                    unique_file2 += 1
                else:
                    style = None  # Default style (no highlight)

                # Insert the line with the appropriate style
                try:
                    doc.insertString(doc.getLength(), line + "\n", style)
                except Exception as e:
                    self.stderr.println("⚠ Error inserting line: {}".format(str(e)))

            # Add final count
            final_count = "\n--- End of Results ---\n"
            try:
                doc.insertString(doc.getLength(), final_count, style_summary)
            except Exception as e:
                self.stderr.println("⚠ Error inserting final count: {}".format(str(e)))
        def compare(type_):
            file1 = file1_path.getText().strip()
            file2 = file2_path.getText().strip()
            fuzzy = fuzzy_match_cb.isSelected()
            
            if not os.path.exists(file1) or not os.path.exists(file2):
                result_area.setText("❌ One or both files not selected or do not exist.")
                return

            endpoints1 = load_csv_endpoints(file1, fuzzy)
            endpoints2 = load_csv_endpoints(file2, fuzzy)

            if type_ == "common":
                result = sorted(endpoints1 & endpoints2)
                result_text = "COMMON ENDPOINTS ({} found):\n\n".format(len(result)) + "\n".join(result) if result else "No common endpoints found."
            else:
                unique1 = sorted(endpoints1 - endpoints2)
                unique2 = sorted(endpoints2 - endpoints1)
                result = unique1 + unique2
                result_text = "UNIQUE ENDPOINTS ({} in File 1, {} in File 2):\n\n".format(len(unique1), len(unique2))
                result_text += "=== Unique to File 1 ===\n" + "\n".join(unique1) + "\n\n" if unique1 else ""
                result_text += "=== Unique to File 2 ===\n" + "\n".join(unique2) if unique2 else ""
                if not unique1 and not unique2:
                    result_text += "No unique endpoints found."

            color_highlight_results(result_text, endpoints1, endpoints2, fuzzy)

        def export_results():
            file1 = file1_path.getText().strip()
            file2 = file2_path.getText().strip()
            fuzzy = fuzzy_match_cb.isSelected()
            
            if not os.path.exists(file1) or not os.path.exists(file2):
                result_area.setText("❌ One or both files not selected or do not exist.")
                return

            endpoints1 = load_csv_endpoints(file1, fuzzy)
            endpoints2 = load_csv_endpoints(file2, fuzzy)

            common = sorted(endpoints1 & endpoints2)
            unique1 = sorted(endpoints1 - endpoints2)
            unique2 = sorted(endpoints2 - endpoints1)

            chooser = JFileChooser()
            ret = chooser.showSaveDialog(panel)
            if ret == JFileChooser.APPROVE_OPTION:
                filename = chooser.getSelectedFile().getAbsolutePath()
                if not filename.endswith('.csv'):
                    filename += '.csv'
                
                try:
                    with open(filename, 'w') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Type', 'Method', 'Endpoint'])
                        
                        # Write unique to file 1
                        for item in unique1:
                            if " " in item:
                                method, endpoint = item.split(" ", 1)
                                writer.writerow(['Unique to File 1', method, endpoint])
                            else:
                                writer.writerow(['Unique to File 1', '', item])
                        
                        # Write unique to file 2
                        for item in unique2:
                            if " " in item:
                                method, endpoint = item.split(" ", 1)
                                writer.writerow(['Unique to File 2', method, endpoint])
                            else:
                                writer.writerow(['Unique to File 2', '', item])
                        
                        # Write common
                        for item in common:
                            if " " in item:
                                method, endpoint = item.split(" ", 1)
                                writer.writerow(['Common', method, endpoint])
                            else:
                                writer.writerow(['Common', '', item])
                    
                    self.stdout.println("✔ Results exported to: {}".format(filename))
                    result_area.setText(result_area.getText() + "\n\n✔ Results exported to: {}".format(filename))
                except Exception as e:
                    self.stderr.println("✖ Error exporting results: {}".format(str(e)))
                    result_area.setText(result_area.getText() + "\n\n✖ Error exporting results: {}".format(str(e)))

        common_button.addActionListener(lambda e: compare("common"))
        unique_button.addActionListener(lambda e: compare("unique"))
        export_button.addActionListener(lambda e: export_results())

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup().addComponent(file1_button).addComponent(file1_path))
                .addGroup(layout.createSequentialGroup().addComponent(file2_button).addComponent(file2_path))
                .addComponent(legend_panel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(common_button)
                    .addComponent(unique_button)
                    .addComponent(export_button)
                    .addComponent(fuzzy_match_cb))
                    .addGroup(layout.createSequentialGroup().addComponent(search_label).addComponent(search_field).addComponent(search_button))
        .addComponent(scroll)
                .addComponent(scroll)
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup().addComponent(file1_button).addComponent(file1_path))
                .addGroup(layout.createParallelGroup().addComponent(file2_button).addComponent(file2_path))
                .addComponent(legend_panel)
                .addGroup(layout.createParallelGroup()
                    .addComponent(common_button)
                    .addComponent(unique_button)
                    .addComponent(export_button)
                    .addComponent(fuzzy_match_cb))
                    .addGroup(layout.createParallelGroup().addComponent(search_label).addComponent(search_field).addComponent(search_button))
                .addComponent(scroll)
        )

        self.main_panel = panel
