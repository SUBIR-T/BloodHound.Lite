import json
import zipfile
import os
import sys
import networkx as nx
from pyvis.network import Network
import argparse

class BloodHoundLite:
    def __init__(self):
        self.graph = nx.DiGraph()

    def load_target(self, path):
        """Loads dataset whether given a zip file, directory, or direct json file."""
        print(f"[+] Loading dataset from: {path}")
        if os.path.isdir(path):
            for fname in os.listdir(path):
                if fname.endswith('.json'):
                    self._parse_file(os.path.join(path, fname))
        elif zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, 'r') as z:
                for filename in z.namelist():
                    if filename.endswith('.json'):
                        content = z.read(filename).decode('utf-8-sig')
                        self._dispatch_parse(filename, json.loads(content))
        elif path.endswith('.json'):
            self._parse_file(path)
        else:
            print(f"[-] Unsupported target format: {path}")

    def _parse_file(self, json_path):
        with open(json_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        self._dispatch_parse(os.path.basename(json_path), data)

    def _dispatch_parse(self, filename, data):
        fname = filename.lower()
        if 'users' in fname:
            self._parse_users(data)
        elif 'groups' in fname or 'group_schema' in fname:
            self._parse_groups(data)
        elif 'computers' in fname:
            self._parse_computers(data)

    def _parse_users(self, data):
        users = data.get("data", data.get("users", [])) if isinstance(data, dict) else data
        for user in users:
            sid = user.get("ObjectIdentifier", "").upper()
            props = user.get("Properties", {})
            name = (props.get("principalname") or props.get("name") or sid).upper()
            if sid:
                node_attrs = {"name": name, "type": "User"}
                node_attrs.update({k: props[k] for k in ["Enabled", "PasswordLastSet", "LastLogon", "DontReqPreAuth"] if k in props})
                self.graph.add_node(sid, **node_attrs)
                self.graph.add_node(name, **node_attrs)

            for ace in user.get("Aces", []):
                principal = (ace.get("PrincipalSID") or ace.get("PrincipalName") or "").upper()
                right = ace.get("RightName", "ACE")
                if sid and principal:
                    self.graph.add_edge(sid, principal, label=right)

    def _parse_groups(self, data):
        groups = data.get("data", data.get("groups", [])) if isinstance(data, dict) else data
        for group in groups:
            sid = group.get("ObjectIdentifier", "").upper()
            props = group.get("Properties", {})
            name = (props.get("principalname") or props.get("name") or sid).upper()
            if sid:
                node_attrs = {"name": name, "type": "Group"}
                node_attrs.update({k: props[k] for k in ["Description"] if k in props})
                self.graph.add_node(sid, **node_attrs)
                self.graph.add_node(name, **node_attrs)

            for member in group.get("Members", []):
                m_id = (member.get("MemberId") or member.get("ObjectIdentifier") or "").upper()
                if m_id and sid:
                    self.graph.add_edge(m_id, sid, label="MemberOf")

    def _parse_computers(self, data):
        computers = data.get("data", data.get("computers", [])) if isinstance(data, dict) else data
        for comp in computers:
            sid = comp.get("ObjectIdentifier", "").upper()
            props = comp.get("Properties", {})
            name = (props.get("name") or props.get("dNSHostName") or sid).upper()
            if sid:
                node_attrs = {"name": name, "type": "Computer"}
                node_attrs.update({k: props[k] for k in ["OperatingSystem", "ProcessorArchitecture"] if k in props})
                self.graph.add_node(sid, **node_attrs)
                self.graph.add_node(name, **node_attrs)

            for admin in comp.get("LocalAdmins", []):
                a_id = (admin.get("ObjectIdentifier") or admin.get("Name") or "").upper()
                if a_id and sid:
                    self.graph.add_edge(a_id, sid, label="AdminTo")

    def find_nodes_by_property(self, prop_name, prop_value, case_sensitive=False):
        """Finds nodes that have a specific property with a given value."""
        matching_nodes = []
        for node_id, data in self.graph.nodes(data=True):
            if prop_name in data:
                if case_sensitive:
                    if data[prop_name] == prop_value:
                        matching_nodes.append(node_id)
                else:
                    if str(data[prop_name]).upper() == str(prop_value).upper():
                        matching_nodes.append(node_id)
        return matching_nodes

    def list_node_relationships(self, node_id):
        """Lists incoming and outgoing relationships for a given node."""
        node_id = node_id.upper() # Ensure case consistency
        if node_id not in self.graph:
            print(f"[-] Node '{node_id}' not found in graph.")
            return

        print(f"\n[+] Relationships for node: {self.graph.nodes[node_id].get('name', node_id)}")
        print("--- Outgoing Relationships ---")
        if self.graph.out_degree(node_id) == 0:
            print("    No outgoing relationships.")
        for neighbor, edge_data in self.graph[node_id].items():
            for _, data in edge_data.items(): # Iterate over multiple edges between same nodes if they exist
                target_name = self.graph.nodes[neighbor].get('name', neighbor)
                print(f"    - {data.get('label', 'UNKNOWN')} -> {target_name} ({neighbor})")

        print("--- Incoming Relationships ---")
        if self.graph.in_degree(node_id) == 0:
            print("    No incoming relationships.")
        for neighbor, edge_data in self.graph.pred[node_id].items():
            for _, data in edge_data.items(): # Iterate over multiple edges between same nodes if they exist
                source_name = self.graph.nodes[neighbor].get('name', neighbor)
                print(f"    - {source_name} ({neighbor}) -{data.get('label', 'UNKNOWN')}-> {self.graph.nodes[node_id].get('name', node_id)}")


    def list_matching_nodes(self, search_term):
        search_term = search_term.upper()
        return [node for node in self.graph.nodes() if search_term in node]

    def find_path_and_export(self, source, target, output_html="attack_path.html"):
        source_clean, target_clean = source.upper(), target.upper()

        for node_name, label in [(source_clean, "Source"), (target_clean, "Target")]:
            if node_name not in self.graph:
                print(f"[-] {label} node '{node_name}' not found in graph.")
                keyword = node_name.split("@")[0]
                matches = self.list_matching_nodes(keyword)
                if matches:
                    print(f"[?] Did you mean one of these loaded nodes for '{keyword}'?")
                    for m in matches[:10]:
                        print(f"    - {m}")
                else:
                    print(f"[?] No nodes matching '{keyword}' were found in dataset.")
                return

        try:
            path = nx.shortest_path(self.graph, source=source_clean, target=target_clean)
            print(f"\n[+] Shortest Attack Path Found:\n " + " -> ".join(path) + "\n")

            net = Network(height="750px", width="100%", directed=True, notebook=False)
            subgraph = self.graph.subgraph(path)

            for node_id in subgraph.nodes():
                node_data = self.graph.nodes[node_id]
                label = node_data.get("name", node_id)
                node_type = node_data.get("type", "Unknown")
                color = "blue"  # Default for User
                if node_type == "Group":
                    color = "green"
                elif node_type == "Computer":
                    color = "red"

                # Add more details to the title for tooltip on hover
                title = f"ID: {node_id}<br>Type: {node_type}"
                for prop, value in node_data.items():
                    if prop not in ["name", "type"]:
                        title += f"<br>{prop}: {value}"

                net.add_node(node_id, label=label, color=color, title=title)

            for u, v, data in subgraph.edges(data=True):
                edge_label = data.get("label", "")
                net.add_edge(u, v, title=edge_label, label=edge_label)

            net.save_graph(output_html)
            print(f"[+] Interactive visual report saved to: {output_html}")

        except nx.NetworkXNoPath:
            print(f"[-] No attack path found between {source_clean} and {target_clean}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BloodHoundLite - A lightweight BloodHound data analyzer.")
    parser.add_argument("input_path", help="Path to the BloodHound data (JSON file, ZIP file, or directory).")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Subparser for 'path' command
    path_parser = subparsers.add_parser("path", help="Find an attack path between two nodes.")
    path_parser.add_argument("start_node", help="Starting node for the attack path.")
    path_parser.add_argument("target_node", help="Target node for the attack path.")
    path_parser.add_argument("--output", default="attack_path.html", help="Output HTML file for the path visualization.")

    # Subparser for 'query' command
    query_parser = subparsers.add_parser("query", help="Query nodes by properties.")
    query_parser.add_argument("property_name", help="Name of the property to query (e.g., 'type', 'OperatingSystem').")
    query_parser.add_argument("property_value", help="Value of the property to search for (e.g., 'User', 'Windows Server 2019 Standard').")
    query_parser.add_argument("--case_sensitive", action="store_true", help="Perform a case-sensitive search.")

    # Subparser for 'relations' command
    relations_parser = subparsers.add_parser("relations", help="List incoming and outgoing relationships for a node.")
    relations_parser.add_argument("node_id", help="ID of the node to query relationships for.")

    args = parser.parse_args()

    app = BloodHoundLite()
    app.load_target(args.input_path)

    if args.command == "path":
        app.find_path_and_export(args.start_node, args.target_node, args.output)
    elif args.command == "query":
        matching_nodes = app.find_nodes_by_property(args.property_name, args.property_value, args.case_sensitive)
        if matching_nodes:
            print(f"\n[+] Found {len(matching_nodes)} nodes with {args.property_name} = {args.property_value}:")
            for node in matching_nodes:
                print(f"    - {node}")
        else:
            print(f"[-] No nodes found with {args.property_name} = {args.property_value}.")
    elif args.command == "relations":
        app.list_node_relationships(args.node_id)
    else:
        parser.print_help()
