import argparse
import json
import os
from pathlib import Path

import requests
import yaml

from LinkToCre.ModifyCre import modify_local_cres

IGNORED_STANDARDS = ['Cloud Controls Matrix',
                     'OWASP Web Security Testing Guide (WSTG)', 'OWASP Proactive Controls', 'OWASP Cheat Sheets',
                     'CAPEC', 'CWE', 'OWASP Secure Headers Project']
nodes = {}
visited_nodes = []
links = set()
ltype = {
    'Contains': "Rel_Specialization(to, from)\n",
    'Related': "Rel_Association(from, to)\n",
    'Linked To': "Rel_Realization(to, from)\n",
    'SAME': "Rel_Access_rw(from, to)\n",
    'Is Part Of': "Rel_Specialization(from, to)\n"
}
root = ''

def parse_child_cre(parent, child, allowed_link_types):
    child_document_name_ = child['document']['name']
    if 'id' not in child['document']:
        child_document_id_ = str(hash(child_document_name_ + child['document']['section']))
    else:
        child_document_id_ = child['document']['id']
    if child_document_id_ not in nodes:
        child_document_doctype_ = child['document']['doctype']
        if child_document_doctype_ == 'Standard' and child_document_name_ not in IGNORED_STANDARDS:
            nodes[child_document_id_] = {'id': '', 'node': '', 'children': set(), 'parents': set()}
            heading = child_document_name_
            if 'sectionID' in child['document'] and (
                    'section' in child['document'] and child['document']['sectionID'] not in child['document'][
                'section']):
                heading = heading + " " + child['document']['sectionID'].replace('"', "'")
            std_id = "STD" + ''.join(filter(str.isalnum, child_document_id_))
            nodes[child_document_id_]['id'] = std_id
            node_type = 'Motivation_Principle'
            if child_document_name_ in ['SAMM', 'OWASP Web Security Testing Guide (WSTG)']:
                node_type = 'Motivation_Assessment'
            elif child_document_name_ in ['ASVS', 'NIST SSDF']:
                node_type = 'Motivation_Requirement'
            elif child_document_name_ in ['OWASP Top 10 2021', 'CWE', 'CAPEC']:
                node_type = 'Motivation_Constraint'
            elif child_document_name_ in ['NIST Privacy Framework', 'NIST Cyber Security Framework']:
                node_type = 'Motivation_Outcome'
            nodes[child_document_id_]['node'] = node_type + "(" + std_id + ", \"=" + heading + "\\n" + \
                                                child['document']['section'].replace('"', "'") + "\")\n"
            nodes[child_document_id_]['parents'].add(
                (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", std_id), parent))
            nodes[parent]['children'].add(
                (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", std_id), child_document_id_))
        if child_document_doctype_ == 'CRE':
            if os.path.exists('resources/cres/modified/' + child_document_id_ + '.yaml'):
                path = 'resources/cres/modified/' + child_document_id_ + '.yaml'
            else:
                path = 'resources/cres/' + child_document_id_ + '.yaml'
            with open(path, 'r', encoding='utf-8') as local_cre_file:
                cre = yaml.full_load(local_cre_file.read())
            cre_id = "CRE" + ''.join(filter(str.isalnum, cre['id']))
            nodes[parent]['children'].add(
                (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", cre_id), child_document_id_))
            me = {'id': cre_id,
                  'node': "Motivation_Goal(" + cre_id + ", \"=CRE" + cre['id'] + "\\n" + cre['name'].replace('"', "'")
                          + "\")\n",
                  'children': set(),
                  'parents': set()}
            me['parents'].add(
                (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", cre_id), parent))
            nodes[child_document_id_] = me
            for link in cre['links']:
                if link['ltype'] in allowed_link_types and link['document']['doctype'] in ['Standard', 'CRE']:
                    parse_child_cre(parent=cre['id'], child=link, allowed_link_types=allowed_link_types)
    else:
        if 'parents' not in nodes[child_document_id_]:
            nodes[child_document_id_]['parents'] = set()
        nodes[child_document_id_]['parents'].add((ltype[child['ltype']].replace("from", nodes[parent]['id']).replace(
            "to", nodes[child_document_id_]['id']), parent))
        nodes[parent]['children'].add(
            (ltype[child['ltype']].replace("from", nodes[parent]['id']).replace("to", nodes[child_document_id_]['id']), child_document_id_))


def add_child(child, depth, cre_file):
    if depth == 0:
        return
    cre_file.write(nodes[child[1]]['node'])
    links.add(child[0])
    for child in nodes[child[1]]['children']:
        if child[1].replace('-', '') != root:
            add_child(child, depth-1, cre_file)


def save_children(child):
    if child['document']['doctype'] == 'CRE' and child['document']['id'] not in visited_nodes:
        cre = json.loads(requests.get('https://www.opencre.org/rest/v1/id/' + child['document']['id']).text)[
            'data']
        with open('resources/cres/' + cre['id'] + '.yaml', 'w', encoding='utf-8') as fetched_cre:
            yaml.dump(cre, fetched_cre)
            print('Updating ' + cre['id'] + ': ' + cre['name'])
        visited_nodes.append(cre['id'])
        for link in cre['links']:
            if link['ltype'] != "Is Part Of":
                save_children(link)


def main(args):
    global root
    global visited_nodes
    global links
    global nodes
    if args.update:
        update_local_cres()
    if args.cre:
        build_cre_tree(args)
    elif args.root_trees:
        root_cres = json.loads(requests.get('https://www.opencre.org/rest/v1/root_cres').text)['data']
        for cre in root_cres:
            nodes = {}
            visited_nodes = []
            links = set()
            root = cre
            build_cre_tree(args)
    else:
        list_cres()


def update_local_cres():
    root_cres = json.loads(requests.get('https://www.opencre.org/rest/v1/root_cres').text)['data']
    for cre in root_cres:
        with open('resources/cres/' + cre['id'] + '.yaml', 'w', encoding='utf-8') as fetched_cre:
            yaml.dump(cre, fetched_cre)
            print('Updating ' + cre['id'] + ': ' + cre['name'])
        for link in cre['links']:
            save_children(link)
    modify_local_cres()


def list_cres():
    files = Path('resources/cres').glob('*.yaml')
    for file in files:
        with open(file, 'r', encoding='utf-8') as cre_file:
            cre = yaml.full_load(cre_file)
            print('CRE ' + cre['id'] + ': ' + cre['name'])


def build_cre_tree(args):
    global root
    file_name = 'resources/cres/' + args.cre + '.yaml'
    if os.path.exists('resources/cres/modified/' + args.cre + '.yaml'):
        file_name = 'resources/cres/modified/' + args.cre + '.yaml'
    with open(file_name, 'r', encoding='utf-8') as root_cre_file:
        cre = yaml.full_load(root_cre_file.read())
    root = cre['id'].replace('-', '')
    cre_file = open(args.cre + ".puml", "w", encoding='utf-8')
    cre_file.write(
        "@startuml CRE" + cre['id'] + " " + cre['name'] + "\n!include <archimate/Archimate>\nleft to right direction\n")
    cre_file.write("Motivation_Driver(CRE" + root + ", \"=CRE " + cre['id'] + "\\n" + cre['name'] + "\")\n")
    nodes[root] = {'id': 'CRE' + root,
                   'node': "Motivation_Driver(CRE" + root + ", \"=CRE " + cre['id'] + "\\n" + cre[
                       'name'] + "\")\n", 'children': set()}
    for link in cre['links']:
        if link['document']['doctype'] in ['CRE', 'Standard']:
            parse_child_cre(root, link, args.link_types)
    for child in nodes[root]['children']:
        add_child(child, args.depth + 1, cre_file)
    for link in links:
        cre_file.write(link)
    cre_file.write("@enduml")
    cre_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Use given CRE as root for a tree')
    parser.add_argument('-c', '--cre', metavar='xxx-yyy', type=str, required=False, dest='cre',
                        help='CRE Id to use as root-node')
    parser.add_argument('-r', '--create-root-trees', action='store_true', dest='root_trees', help='Shortcut for creating trees based on the root-cres')
    parser.add_argument('-u', '--update', action='store_true', dest='update', help='Update the local copy of CREs')
    parser.add_argument('-d', '--depth', metavar='N', type=int, default=1, required=False, dest='depth',
                        help='Depth, default 1')
    parser.add_argument('--allowed-link-types', choices=['Contains', 'Part Of', 'Linked To', 'Related', 'SAME'],
                        default=['Contains', 'Linked To', 'Related'],
                        required=False, dest='link_types', help='Which type of links to include')
    args = parser.parse_args()
    main(args)

