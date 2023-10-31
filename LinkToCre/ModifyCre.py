from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
import yaml
from dacite import from_dict, Config

from LinkToCre.Cre import Link, Document, Credoctypes, CRE, Standard, LinkTypes
from LinkToCre.NistPrivacyFramework import dump_standard_to_cre_format

EXTERNAL_STANDARDS_PREFIXES = ['CM.', 'CT.', 'GV.', 'ID.', 'PR.', 'DE.', 'RS.', 'RC.']
cres = []
documents = {}
reverse_document_links = {}

def parse_file(yamldocs: List[Dict[str, Any]]) -> Optional[List[Document]]:
    resulting_objects = []
    for contents in yamldocs:
        links = []

        document: Optional[Document] = None
        register_callback: Optional[Callable[[Any, Any], Any]] = None

        if not isinstance(contents, dict):
            return None

        if contents.get("links"):
            links = contents.pop("links")

        if contents.get("doctype") == Credoctypes.CRE.value:
            document = from_dict(
                data_class=CRE,
                data=contents,
                config=Config(cast=[Credoctypes]),
            )
        elif contents.get("doctype") == Credoctypes.Standard.value:
            doctype = contents.get("doctype")
            data_class = (Standard if doctype == Credoctypes.Standard.value else None)
            document = from_dict(
                data_class=data_class,
                data=contents,
                config=Config(cast=[Credoctypes]),
            )
        else:
            return []
        for link in links:
            document_links = []
            document_links.append(link["document"])
            doclink = parse_file(yamldocs=document_links)

            if doclink:
                if len(doclink) > 1:
                    raise RuntimeError("Parsing single document returned 2 results this is a bug")
                document.add_link(Link(document=doclink[0], ltype=link["ltype"], tags=link["tags"] if 'tags' in link else None))
                doc_id = document.id
                if document.id.strip() == '':
                    if document.name == 'NIST 800-53 v5':
                        doc_id = document.section.strip().replace('(', ' ').split(' ')[0]
                    else:
                        doc_id = document.sectionID.strip()
                link_id = doclink[0].id.strip()
                if doclink[0].doctype != Credoctypes.CRE and doclink[0].id == '':
                    if doclink[0].name == 'NIST 800-53 v5':
                        link_id = doclink[0].section.strip().replace('(', ' ').split(' ')[0]
                    else:
                        link_id = doclink[0].sectionID.strip()
                if link_id not in reverse_document_links:
                    reverse_document_links[link_id] = {Credoctypes.Standard.value: {}, Credoctypes.CRE.value: {}}
                if doc_id not in reverse_document_links:
                    reverse_document_links[doc_id] = {Credoctypes.Standard.value: {}, Credoctypes.CRE.value: {}}
                reverse_document_links[link_id][document.doctype.value][doc_id] = link["ltype"]
                reverse_document_links[doc_id][doclink[0].doctype.value][link_id] = link["ltype"]
        resulting_objects.append(document)
    return resulting_objects


def modify_local_cres():
    global cre
    files = Path('../resources/cres').glob('*.yaml')
    for file in files:
        print(file)
        with open(file, 'r', encoding='utf-8') as cre_file:
            cre = yaml.full_load(cre_file)
            cres.append(cre)
    dump_standard_to_cre_format()
    files = Path('../resources/standards').glob('*.yaml')
    for file in files:
        print(file)
        with open(file, 'r', encoding='utf-8') as cre_file:
            cre = yaml.full_load(cre_file)
            cres.append(cre)
    res = parse_file(cres)
    for cre in res:
        if cre.id != '':
            documents[cre.id] = cre
        else:
            if cre.name == "NIST 800-53":
                documents[cre.section.replace('(', ' ').split(' ')[0]] = cre
            else:
                documents[cre.sectionID] = cre
    for link in reverse_document_links.keys():
        if any(link.startswith(x) for x in EXTERNAL_STANDARDS_PREFIXES):
            pf_link = Link(document=documents[link].shallow_copy(), ltype=LinkTypes.LinkedTo)
            for rev_link in reverse_document_links[link]['Standard']:
                if rev_link in reverse_document_links.keys():
                    if reverse_document_links[rev_link]['CRE']:
                        cre_keys = reverse_document_links[rev_link]['CRE'].keys()
                        print(link, cre_keys)
                        for key in cre_keys:
                            cre_doc = documents[key]
                            cre_doc.add_link(pf_link)
                            documents[key] = cre_doc
                            with open('../resources/cres/modified/' + cre_doc.id + '.yaml', 'w',
                                      encoding='utf-8') as cre_file:
                                yaml.dump(cre_doc.todict(), cre_file)


if __name__ == "__main__":
    modify_local_cres()
