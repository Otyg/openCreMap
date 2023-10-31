import json

import requests

root_cres = json.loads(requests.get('https://www.opencre.org/rest/v1/root_cres').text)['data']


class Link:
    ltype = {
        'Contains': "Rel_Specialization(to, from)\n",
        'Related': "Rel_Association(from, to)\n",
        'Linked To': "Rel_Realization(to, from)\n",
        'SAME': "Rel_Influence(from, to)\n"
    }

    def __init__(self, source, destination, type):
        self.source = source
        self.destination = destination
        self.type = type

    def __hash__(self):
        return hash(hash(self.source) + hash(self.destination) + hash(self.type))

    def __eq__(self, other):
        if self.type == "Related" and other.type == "Related":
            return (self.source == other.source and self.destination == other.destination) or \
                   (self.source == other.destination and self.destination == other.source)
        else:
            return (self.source, self.destination, self.type) == (other.source, other.destination, other.type)

    def __str__(self):
        return self.ltype[self.type].replace('from', self.source).replace('to', self.destination)


def parse_child_cre(parent, child):
    if 'id' not in child['document']:
        child['document']['id'] = str(hash(child['document']['name'] + child['document']['section']))
    if child['document']['id'] not in nodes:
        doc_id = ""
        if child['document']['doctype'] == 'Standard' and child['document']['name'] not in ['OWASP Web Security Testing Guide (WSTG)','OWASP Cheat Sheets', 'Cheat_sheets', 'CAPEC', 'CWE', 'Cloud Controls Matrix', 'OWASP Proactive Controls']:
            if child['document']['name'] in ['ASVS']:
                base_leaf_nodes.add(child['document']['id'])
            nodes[child['document']['id']] = {'id': '', 'node': '', 'children': {'Standard': {}, 'CRE': {}}, 'parents': set()}
            heading = child['document']['name']
            if 'sectionID' in child['document']:
                heading = heading + " " + child['document']['sectionID'].replace('"', "'")
            doc_id = "STD" + ''.join(filter(str.isalnum, child['document']['id']))
            nodes[child['document']['id']]['id'] = doc_id
            node_type = 'Motivation_Principle'
            if child['document']['name'] in ['SAMM']:
                node_type = 'Motivation_Assessment'
            elif child['document']['name'] in ['ASVS', 'NIST SSDF']:
                node_type = 'Motivation_Requirement'
            elif child['document']['name'] in ['OWASP Top 10 2021', 'CWE', 'CAPEC']:
                node_type = 'Motivation_Constraint'
            nodes[child['document']['id']]['node'] = node_type + "(" + doc_id + ", \"=" + heading + "\\n" + \
                                                     child['document']['section'].replace('"', "'") + "\")\n"
            nodes[child['document']['id']]['parents'].add(parent)

            print("Standard " + heading + " added")
        if child['document']['doctype'] == 'CRE':
            cre = json.loads(requests.get('https://www.opencre.org/rest/v1/id/' + child['document']['id']).text)['data']
            doc_id = "CRE" + ''.join(filter(str.isalnum, cre['id']))
            me = {'id': doc_id,
                  'node': "Motivation_Goal(" + doc_id
                          + ", \"=CRE" + cre['id'] + "\\n"
                          + cre['name'].replace('"', "'") + "\")\n",
                  'children': {'Standard': {}, 'CRE': {}},
                  'parents': set()}
            me['parents'].add(parent)
            nodes[child['document']['id']] = me
            print("CRE " + cre['id'] + " added")
            for link in cre['links']:
                if link['ltype'] not in ["Is Part Of", "Related"] and link['document']['doctype'] in ['Standard', 'CRE']:
                    parse_child_cre(parent=cre['id'], child=link)
                elif current_root == '546-564' and link['document']['doctype'] in ['Standard', 'CRE'] and link[
                    'ltype'] == "Related" and cre['id'] in ["155-155", "486-813", "170-772", "028-727", "623-550",
                                                            "760-764", "362-550", "058-527", "028-727", "760-765"]:
                    parse_child_cre(parent=cre['id'], child=link)

        if doc_id != "":
            if child['document']['id'] not in nodes[parent]['children'][child['document']['doctype']]:
                nodes[parent]['children'][child['document']['doctype']][child['document']['id']] = []
            nodes[parent]['children'][child['document']['doctype']][child['document']['id']].append(
                Link(source=nodes[parent]['id'], destination=doc_id, type=child['ltype'])
            )
    else:
        if 'parents' not in nodes[child['document']['id']]:
            nodes[child['document']['id']]['parents'] = set()
        if child['document']['id'] not in nodes[parent]['children'][child['document']['doctype']]:
            nodes[parent]['children'][child['document']['doctype']][child['document']['id']] = []
        nodes[child['document']['id']]['parents'].add(parent)
        nodes[parent]['children'][child['document']['doctype']][child['document']['id']].append(Link(source=nodes[parent]['id'], destination=nodes[child['document']['id']]['id'],type=child['ltype']))


def build_parent_tree(parents, child):
    print("Building subtree " + nodes[child]['id'])
    for parent in parents:
        print("Node " + nodes[parent]['id'])
        if 'parents' in nodes[parent]:
            if parent not in visited_nodes:
                print("Not visited")
                visited_nodes.add(parent)
                build_parent_tree(nodes[parent]['parents'], parent)
                file.write(nodes[parent]['node'])
        elif parent not in visited_nodes:
            print("Is root")
            file.write(nodes[parent]['node'])
            visited_nodes.add(parent)
        parent_links = None
        if child in nodes[parent]['children']['Standard']:
            parent_links = nodes[parent]['children']['Standard'][child]
        elif child in nodes[parent]['children']['CRE']:
            parent_links = nodes[parent]['children']['CRE'][child]
        for link in parent_links:
            print("Add link " + str(link))
            links.add(link)
    if 'children' in nodes[child]:
        for std in nodes[child]['children']['Standard']:
            visited_nodes.add(std)
            file.write(nodes[std]['node'])
            for link in nodes[child]['children']['Standard'][std]:
                links.add(link)


nodes = {}
links = set()
base_leaf_nodes = set()
visited_nodes = set()
current_root = ""
print('Building Tree')
for cre in root_cres:
    current_root = cre
    cre_alphanumeric = "CRE" + ''.join(filter(str.isalnum, cre['id']))
    print("Parsing root CRE" + cre['id'] + " " + cre['name'])
    nodes[cre['id']] = {'id': cre_alphanumeric,
                        'node': "Motivation_Goal(" + cre_alphanumeric + ", \"=CRE " + cre['id'] + "\\n" + cre[
                            'name'] + "\")\n", 'children': {'Standard': {}, 'CRE': {}}}

    for link in cre['links']:
        if link['document']['doctype'] in ['Standard', 'CRE']:
            parse_child_cre(cre['id'], link)

print("Creating reverse tree")
with open('asvs_connections.puml', 'w', encoding='utf-8') as file:
    file.write("@startuml SAMM Connections\n!include <archimate/Archimate>\n")
    file.write("!define SAMM(e_alias, e_label) archimate #DarkGoldenRod \"e_label\" <<motivation-assessment>> as e_alias\nleft to right direction\n")
    for node in base_leaf_nodes:
        file.write(nodes[node]['node'])
    for node in base_leaf_nodes:
        print('Base Node ' + nodes[node]['id'])
        visited_nodes.add(node)
        build_parent_tree(nodes[node]['parents'], node)
    for link in links:
        file.write(str(link))
    file.write("@enduml")
    file.close()
