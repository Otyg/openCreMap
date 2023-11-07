import json
import random
import string
import time

import requests

import yaml

from LinkToCre.Cre import Standard, Link, LinkTypes

privacy_framework = {}
mappings = {}
external_data = {}
skipped_mappings = []


def read_mappings():
    global raw_privacy_framework, raw_cybersecurity_framework
    with open('resources/NIST-PF-Core.txt', 'r', encoding='utf-8') as pf_file:
        raw_privacy_framework = pf_file.readlines()
    with open('resources/NIST-CSF-Core.txt', 'r', encoding='utf-8') as csf_file:
        raw_cybersecurity_framework = csf_file.readlines()
    with open('resources/NIST-PF-to-800-53.txt', 'r', encoding='utf-8') as mapping_file:
        raw_mappings = mapping_file.readlines()
    with open('resources/NIST-CSF-to-800-53.txt', 'r', encoding='utf-8') as mapping_file:
        for mapping in mapping_file.readlines():
            raw_mappings.append(mapping)
    for mapping in raw_mappings:
        pf_id = mapping.split(':')[0]
        external_ids = mapping.split(':')[1] \
            .replace('\n', '') \
            .replace('all -1 controls\n', '') \
            .replace('all -1 controls, ', '') \
            .replace('all -1 controls', '') \
            .split(', ')
        if '' in external_ids:
            external_ids.remove('')
        if len(external_ids) > 0:
            mappings[pf_id] = external_ids


def fetch_external(external_id, retries=0):
    if retries > 10:
        raise RuntimeError('Number of retries exceeded')
    try:
        time.sleep(random.randint(1*retries, (6*retries)+1))
        response = requests.get(
            'https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_53_5_1_0/element/' + external_id + '/graph',
            timeout=10)
        if response.status_code != 200:
            requests.exceptions.RequestException(response.status_code)
        json_response = json.loads(response.text)
        external_data[external_id] = json_response['response']['elements'][0]['elements'][0]
        print(external_id + ' ' + string.capwords(external_data[external_id]['title']) + ' fetched')
    except (requests.exceptions.ReadTimeout, requests.exceptions.RequestException) as e:
        print('Timeout, ' + str(10-retries) + ' retries to go')
        fetch_external(external_id, retries+1)


def create_standard(framework='NIST Privacy Framework', version='1.0.0', standard_endpoint='PF_1_0_0'):
    global section
    leaf = False
    section = line.split(':')
    pf_section = Standard(name=framework)
    pf_section.version = version
    if '(' in section[0]:
        print(section[0])
        section_split = section[0].split('(')
        pf_section.section = section_split[1][:-1] + ' ' + section_split[0][:-1]
        pf_section.sectionID = section_split[1][:-1]
        if '.' in pf_section.sectionID:
            if framework == 'NIST Privacy Framework':
                parent_id = pf_section.sectionID.split('.')[0] + '-P'
            else:
                parent_id = pf_section.sectionID.split('.')[0]
            link = Link(document=privacy_framework[parent_id].shallow_copy())
            link.ltype = LinkTypes.PartOf
            pf_section.add_link(link)
            leaf = True
    else:
        print(section[0])
        pf_section.sectionID = section[0]
        pf_section.section = section[1].replace("\n", "").strip()
        if framework == 'NIST Privacy Framework':
            link = Link(document=privacy_framework[pf_section.sectionID[:-1]].shallow_copy())
        else:
            link = Link(document=privacy_framework[pf_section.sectionID.split('-')[0]].shallow_copy())
        link.ltype = LinkTypes.PartOf
        pf_section.add_link(link)
        leaf = True
    pf_section.hyperlink = 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/' + standard_endpoint + '/home?element=' + pf_section.sectionID
    if leaf:
        parent_link = Link(document=pf_section.shallow_copy())
        parent_link.ltype = LinkTypes.Contains
        privacy_framework[link.document.sectionID].add_link(parent_link)
        print('Added parent link')
    if pf_section.sectionID in mappings:
        for external_id in mappings[pf_section.sectionID]:
            print('Adding external standard ' + external_id)
            unmodified_external_id = external_id
            if '(' in external_id:
                external_id = external_id.split('(')[0]
            if external_id not in external_data:
                fetch_external(external_id)
            link = Link(document=Standard(
                name='NIST 800-53 v5',
                section=external_id + ' ' + string.capwords(external_data[external_id]['title']),
                hyperlink='https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/sp_800_53_5_1_0/home?element=' +
                          external_id
            ), ltype=LinkTypes.Related)
            pf_section.add_link(link)
            print(external_id + ' added')
    privacy_framework[pf_section.sectionID] = pf_section
    print(pf_section.sectionID + ' added')


def dump_standard_to_cre_format():
    read_mappings()
    global line, section
    for line in raw_privacy_framework:
        create_standard()
    for line in raw_cybersecurity_framework:
        create_standard(framework='NIST Cyber Security Framework', version='1.1.0', standard_endpoint='CSF_1_1_0')
    for section in privacy_framework:
        with open('resources/standards/' + section + '.yaml', 'w', encoding='utf-8') as section_file:
            yaml.dump(privacy_framework[section].todict(), section_file)
