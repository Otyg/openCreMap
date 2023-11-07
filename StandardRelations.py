import argparse
import ctypes
from pathlib import Path
from typing import Dict, Any
import urllib.parse
import requests
import json

import yaml

standards = ['SAMM', 'NIST 800-63', 'OWASP Top 10 2021', 'ISO 27001', 'ASVS', 'OWASP Web Security Testing Guide (WSTG)', 'NIST 800-53 v5', 'NIST SSDF', 'Cloud Controls Matrix']
parents = dict()


class Node:
    doctype: str = ''
    name: str = ''
    description: str = ""
    hyperlink: str = ""
    section: str = ""
    sectionID: str = ""
    subsection: str = ""
    node_type: str = 'Motivation_Goal'
    id: str = ''

    def __init__(self, node=Dict[str, Any]):
        self.doctype = node.get('doctype')
        self.name = node.get('name')
        self.description = node.get('description', '')
        self.hyperlink = node.get('hyperlink', '')
        self.section = node.get('section', '')
        self.sectionID = node.get('sectionID', '')
        self.subsection = node.get('subsection', '')
        self.__set_node_type()
        self.id = self.doctype + str(hash(self))

    def __set_node_type(self):
        if self.doctype == 'CRE':
            self.node_type = 'Motivation_Principle'
        else:
            self.node_type = 'Motivation_Goal'
            if self.name in ['SAMM', 'OWASP Web Security Testing Guide (WSTG)']:
                self.node_type = 'Motivation_Assessment'
            elif self.name in ['ASVS', 'NIST SSDF']:
                self.node_type = 'Motivation_Requirement'
            elif self.name in ['OWASP Top 10 2021', 'CWE', 'CAPEC', 'CWE']:
                self.node_type = 'Motivation_Constraint'
            elif self.name in ['NIST Privacy Framework', 'NIST Cyber Security Framework']:
                self.node_type = 'Motivation_Outcome'

    def __hash__(self):
        return ctypes.c_size_t(hash((self.name, self.section, self.sectionID))).value

    def __eq__(self, other):
        return isinstance(other, type(self)) and hash(other) == hash(self)

    def __str__(self):
        heading = self.name
        if self.sectionID != '':
            heading = self.name + " " + self.sectionID
        return self.node_type + "(" + self.id + ", \"=" + heading.replace('"', "'") + "\\n" + self.section.replace('"', "'") + "\")\n"


class Link:

    link_type = {
        'RELATED': 'Rel_Association',
        'CONTAINS': 'Rel_Specialization',
        'LINKED_TO': 'Rel_Realization'
    }

    def __init__(self, source=Node, destination=Node, relation=str, up=bool):
        self.start = source.id
        self.end = destination.id
        self.relation = self.link_type[relation]+'_Up' if up else self.link_type[relation]

    def __hash__(self):
        return hash((self.start, self.end, self.relation))

    def __eq__(self, other):
        equal = False
        if isinstance(other, type(self)) and hash(other) == hash(self):
            equal = True
        elif isinstance(other, type(self)) and (self.relation == 'RELATED' and other.relation == 'RELATED'):
            equal = self.start == other.end and self.end == other.start
        return equal

    def __str__(self):
        return self.relation + "(" + self.start + ', ' + self.end + ")\n"


def main(base_standard, depth, section):
    nodes = set()
    links = set()
    for standard in standards:
        if standard == base_standard:
            continue
        cre_map = requests.get('https://www.opencre.org/rest/v1/map_analysis?standard=' + urllib.parse.quote(base_standard) +'&standard=' + urllib.parse.quote(standard))
        mappings = json.loads(cre_map.text)
        for result in mappings['result']:
            if section != None and (mappings['result'][result]['start']['section'] != section and mappings['result'][result]['start']['sectionID'] != section):
                continue
            paths_ = mappings['result'][result]['paths']
            for path in paths_:
                link = paths_[path]
                if link['score'] <= depth:
                    for step in link['path']:
                        start = Node(node=step['start'])
                        end = Node(node=step['end'])
                        base_relation = base_standard in end.name
                        relation = Link(start, end, step['relationship'], base_relation)
                        nodes.add(start)
                        nodes.add(end)
                        links.add(relation)
                        if 'section' in step['end']:
                            node_id = hash((step['end']['name'], step['end']['section']))
                            if node_id not in parents:
                                parents[node_id] = []
                            parents[node_id].append(start)
    files = Path('resources/standards').glob('*.yaml')
    for file in files:
        with open(file, 'r', encoding='utf-8') as cre_file:
            standard = yaml.full_load(cre_file)
            element = Node(node=standard)
            for document in standard['links']:
                if document['ltype'] == 'Related':
                    rel_id = hash((document['document']['name'], document['document']['section']))
                    if rel_id in parents:
                        for parent in parents[rel_id]:
                            links.add(Link(parent, element, 'LINKED_TO', False))
                            nodes.add(element)
    with open(base_standard.replace(' ', '_')+'.puml', 'w', encoding='utf-8') as out_file:
        out_file.write("@startuml Connections from " + base_standard + ", depth " + str(depth) + "\n!include <archimate/Archimate>\nleft to right direction\n")
        for node in nodes:
            out_file.write(str(node))
        for link in links:
            out_file.write(str(link))
        out_file.write("@enduml")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Show Connections For Given Standard')
    parser.add_argument('-d', '--distance', metavar='N', type=int, required=False, dest='depth', default=0,
                        help='Distance of the connections, default 0 (only direct links)')
    parser.add_argument('-l', '--list-standards', help='List avavailble standards', action='store_true', dest='list')
    parser.add_argument('standard', metavar="STANDARD", default='list', nargs='?')
    parser.add_argument('section', metavar="SECTION", nargs='?')
    args = parser.parse_args()
    if args.list or args.standard == 'list':
        print(standards)
    else:
        main(base_standard=args.standard, depth=args.depth, section=args.section)
