import json
from copy import copy
from dataclasses import field, asdict, dataclass
from enum import Enum, EnumMeta
from typing import Optional, List, Dict, Any, Union, Set

from dacite import from_dict, Config


class EnumMetaWithContains(EnumMeta):
    def __contains__(cls: Enum, item: Any) -> bool:
        return item in [v.value for v in cls.__members__.values()]


class Credoctypes(str, Enum, metaclass=EnumMetaWithContains):
    CRE = "CRE"
    Standard = "Standard"
    Tool = "Tool"
    Code = "Code"

    @staticmethod
    def from_str(typ: str) -> "Credoctypes":
        typ = [t for t in Credoctypes if t in typ]
        if not typ:
            return None
        else:
            return typ[0]


class LinkTypes(str, Enum, metaclass=EnumMetaWithContains):
    Same = "SAME"
    LinkedTo = "Linked To"  # Any standard entry is by default “linked”
    PartOf = "Is Part Of"  # Hierarchy above: “is part of”
    Contains = "Contains"  # Hierarchy below: “Contains”
    Related = "Related"  # Hierarchy across (other CRE topic or Tag): “related”

    RemediatedBy = "Remediated by"
    Remediates = "Remediates"

    TestedBy = "TestedBy"
    Tests = "Tests"

    @staticmethod
    def from_str(name: str) -> Any:  # it returns LinkTypes but then it won't run
        if name.upper().startswith("SAM"):
            name = "SAME"
        res = [x for x in LinkTypes if x.value == name]
        if not res:
            raise KeyError(
                f"{name} is not a valid linktype, supported linktypes are {[t for t in LinkTypes]}"
            )
        return res[0]


@dataclass
class Link:
    document: "Document"
    ltype: LinkTypes = LinkTypes.Same
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

        if type(self.ltype) == str:
            self.ltype = LinkTypes.from_str(self.ltype)

    def __hash__(self) -> int:
        return hash(json.dumps(self.todict()))

    def __repr__(self) -> str:
        return json.dumps(self.todict())

    def __eq__(self, other: object) -> bool:
        return (
            type(other) is Link
            and self.ltype.value == other.ltype.value
            and self.tags == other.tags
            and self.document.__eq__(other.document)
        )

    def todict(self) -> Dict[str, Union[List[str], str, Dict[Any, Any]]]:
        res: Dict[str, Union[List[str], str, Dict[Any, Any]]] = {}
        if self.document:
            res["document"] = self.document.todict()
        else:
            raise ValueError(
                f"Found Link not containing a document, this is a bug, for debugging, the tags for this Link are {self.tags}"
            )
        self.tags = [x for x in self.tags if x != ""]
        if self.tags and len(self.tags):
            res["tags"] = self.tags
        if self.ltype:
            res["ltype"] = "" + self.ltype.value
        else:
            res["ltype"] = "" + 'Unknown'
        return res


@dataclass
class Document:
    name: str
    doctype: Credoctypes
    id: Optional[str] = ""
    description: Optional[str] = ""
    links: List[Link] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, type(self))
            and self.id == other.id
            and self.name == other.name
            and self.doctype.value == other.doctype.value
            and self.description == other.description
            and len(self.links) == len(other.links)
            and all(
                [
                    a in other.links and b in self.links
                    for a in self.links
                    for b in other.links
                ]
            )
            and all(
                [
                    a in other.tags and b in self.tags
                    for a in self.tags
                    for b in other.tags
                ]
            )
            and self.metadata == other.metadata
        )

    def __hash__(self) -> int:
        return hash(json.dumps(self.todict()))

    def shallow_copy(self) -> Any:
        """Returns a copy of itself minus the Links,
        useful when creating links between cres"""
        res = copy(self)
        res.links = []
        return res

    def todict(self) -> Dict[str, Union[Dict[str, str], List[Any], Set[str], str]]:
        res = asdict(
            self,
            dict_factory=lambda x: {
                k: v if type(v) == list or type(v) == set or type(v) == dict else str(v)
                for (k, v) in x
                if v not in ["", {}, [], None, set()]
            },
        )
        res["doctype"] = self.doctype.value + ""
        if "links" in res:
            res["links"] = [l.todict() for l in self.links]
        if "tags" in res:
            res["tags"] = list(self.tags)
        return res

    def __repr__(self):
        return f"{self.todict()}"

    def add_link(self, link: Link) -> "Document":
        if not self.links:
            self.links = []
        if not isinstance(link, Link):
            raise ValueError("add_link only takes Link() types")

        self.links.append(link)
        return self


@dataclass
class CRE(Document):
    doctype: Credoctypes = Credoctypes.CRE


@dataclass
class Node(Document):
    hyperlink: Optional[str] = ""
    version: Optional[str] = ""

    def todict(self):
        res = super().todict()
        if self.hyperlink:
            res["hyperlink"] = self.hyperlink
        return res

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, type(self))
            and super().__eq__(other)
            and self.hyperlink == other.hyperlink
        )


@dataclass
class Standard(Node):
    section: str = ""
    sectionID: str = ""
    doctype: Credoctypes = Credoctypes.Standard
    subsection: Optional[str] = ""

    def todict(self) -> Dict[Any, Any]:
        res = super().todict()
        res["section"] = self.section
        if self.subsection:
            res["subsection"] = self.subsection
        if self.version:
            res["version"] = self.version
        if self.sectionID:
            res["sectionID"] = self.sectionID
        return res

    def __hash__(self) -> int:
        return hash(json.dumps(self.todict()))

    def __eq__(self, other: object) -> bool:
        return (
            super().__eq__(other)
            and self.section == other.section
            and self.subsection == other.subsection
            and self.version == other.version
            and self.sectionID == other.sectionID
        )
