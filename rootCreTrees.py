import json

import requests

root_cres = json.loads(requests.get('https://www.opencre.org/rest/v1/root_cres').text)['data']

ltype = {
    'Contains': "Rel_Specialization(from, to)\n",
    'Related': "Rel_Association(from, to)\n",
    'Linked To': "Rel_Realization(from, to)\n",
    'SAME': "Rel_Access_rw(from, to)\n"
}


def parse_child_cre(parent, child):
    if 'id' not in child['document']:
        child['document']['id'] = str(hash(child['document']['name'] + child['document']['section']))
    if child['document']['id'] not in nodes and child['document']['id'] not in std_nodes:
        if child['document']['doctype'] == 'Standard' and child['document']['name'] not in [
            'OWASP Web Security Testing Guide (WSTG)', 'OWASP Proactive Controls', 'OWASP Cheat Sheets', 'CAPEC',
            'CWE']:
            nodes[child['document']['id']] = {'id': '', 'node': '', 'children': set(), 'parents': set()}
            heading = child['document']['name']
            if 'sectionID' in child['document']:
                heading = heading + " " + child['document']['sectionID'].replace('"', "'")
            std_id = "STD" + ''.join(filter(str.isalnum, child['document']['id']))
            nodes[child['document']['id']]['id'] = std_id
            node_type = 'Motivation_Principle'
            if child['document']['name'] in ['SAMM', 'OWASP Web Security Testing Guide (WSTG)']:
                node_type = 'Motivation_Assessment'
            elif child['document']['name'] in ['ASVS', 'NIST SSDF']:
                node_type = 'Motivation_Requirement'
            elif child['document']['name'] in ['OWASP Top 10 2021', 'CWE', 'CAPEC']:
                node_type = 'Motivation_Constraint'
            nodes[child['document']['id']]['node'] = node_type + "(" + std_id + ", \"=" + heading + "\\n" + \
                                                     child['document']['section'].replace('"', "'") + "\")\n"
            nodes[child['document']['id']]['parents'].add(
                (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", std_id), parent))
            std_nodes.add(child['document']['id'])
            nodes[parent]['children'].add(
                ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", std_id))
            print("Standard " + heading + " added")
        if child['document']['doctype'] == 'CRE':
            cre = json.loads(requests.get('https://www.opencre.org/rest/v1/id/' + child['document']['id']).text)['data']
            cre_id = "CRE" + ''.join(filter(str.isalnum, cre['id']))
            nodes[parent]['children'].add(
                ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", cre_id))
            me = {'id': cre_id,
                  'node': "Motivation_Goal(" + cre_id + ", \"=CRE" + cre['id'] + "\\n" + cre['name'].replace('"',
                                                                                                             "'") + "\")\n",
                  'children': set(),
                  'parents': set()}
            me['parents'].add(
                (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", cre_id), parent))
            nodes[child['document']['id']] = me
            print("CRE " + cre['id'] + " added")
            for link in cre['links']:
                if link['ltype'] != "Is Part Of" and link['ltype'] != "Related" and link['document']['doctype'] in [
                    'Standard', 'CRE']:
                    parse_child_cre(parent=cre['id'], child=link)
                elif nodes['root'] == '546-564' and link['document']['doctype'] in ['Standard', 'CRE'] and link[
                    'ltype'] == "Related" and cre['id'] in ["155-155", "486-813", "170-772", "028-727", "623-550",
                                                            "760-764", "362-550", "058-527", "028-727", "760-765"]:
                    parse_child_cre(parent=cre['id'], child=link)
    else:
        if 'parents' not in nodes[child['document']['id']]:
            nodes[child['document']['id']]['parents'] = set()
        nodes[child['document']['id']]['parents'].add((ltype[child['ltype']].replace("from",
                                                                                     nodes[parent]['id']).replace("to",
                                                                                                                  nodes[
                                                                                                                      child[
                                                                                                                          'document'][
                                                                                                                          'id']][
                                                                                                                      'id']),
                                                       parent))
        nodes[parent]['children'].add(ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", nodes[
            child['document']['id']]['id']))


def build_parent_tree(parents, child):
    print("Building tree " + child)
    for parent in parents:
        print("Node " + nodes[parent[1]]['id'])
        if 'parents' in nodes[parent[1]]:
            if parent[1] not in visited_nodes:
                print("Not visited")
                visited_nodes.add(parent[1])
                build_parent_tree(nodes[parent[1]]['parents'], nodes[parent[1]]['id'])
                cre_file.write(nodes[parent[1]]['node'])
        elif parent[1] not in visited_nodes:
            print("Is root")
            # cre_file.write(nodes[parent[1]]['node'])
            visited_nodes.add(parent[1])
        links.add(parent[0])
        print("Link added")


for cre in root_cres:
    nodes = {}
    links = set()
    std_nodes = set()
    visited_nodes = set()
    nodes['root'] = cre['id']
    cre_alphanumeric = "CRE" + ''.join(filter(str.isalnum, cre['id']))
    print("Parsing root CRE" + cre['id'] + " " + cre['name'])
    cre_file = open(cre_alphanumeric + ".puml", "w", encoding='utf-8')
    cre_file.write(
        "@startuml CRE" + cre['id'] + " " + cre['name'] + "\n!include <archimate/Archimate>\nleft to right direction\n")
    cre_file.write("Motivation_Driver(" + cre_alphanumeric + ", \"=CRE " + cre['id'] + "\\n" + cre['name'] + "\")\n")
    nodes[cre['id']] = {'id': cre_alphanumeric,
                        'node': "Motivation_Driver(" + cre_alphanumeric + ", \"=CRE " + cre['id'] + "\\n" + cre[
                            'name'] + "\")\n", 'children': set()}

    for link in cre['links']:
        if link['document']['doctype'] in ['Standard', 'CRE']:
            parse_child_cre(cre['id'], link)

    print("Creating reverse tree")
    for node in std_nodes:
        print('Node ' + nodes[node]['id'])
        visited_nodes.add(node)
        build_parent_tree(nodes[node]['parents'], nodes[node]['id'])
    for node in std_nodes:
        cre_file.write(nodes[node]['node'])
    for link in links:
        cre_file.write(link)
    cre_file.write("@enduml")
    cre_file.close()
