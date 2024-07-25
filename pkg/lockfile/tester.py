"""

Helper script, remember to remove later!!
"""

import sys
import re
from dataclasses import dataclass

expectCommit = True
expectDepGroups = True
startKey = "ParseMixLock"


@dataclass
class InventoryItem:
    """Class for keeping track of an item in inventory."""
    name: str
    version: str
    commit: str = ""
    depGroups: list[str] = None


def genInventory(path, valueList: list[InventoryItem]) -> str:
    buildStr = ""
    for i in valueList:
        current = f"""
        {{
            Name:      "{i.name}",
            Version:   "{i.version}",
            Locations: []string{{"{path}"}},
"""
        if expectCommit:
            current += f'SourceCode: &lockfile.SourceCodeIdentifier{{\nCommit: "{i.commit}",\n}},\n'

        if expectDepGroups:
            current += f"Metadata: lockfile.DepGroupMetadata{{\nDepGroupVals: []string{{{', '.join(i.depGroups or [])}}},\n}},\n"

        current += '},'
        buildStr += current
    return buildStr


def outputValue(path, funcName, inventory: list[InventoryItem]):
    name = re.sub(r'(?<!^)(?=[A-Z])', ' ', funcName).lower()

    template = '''{{
			name: "{name}",
			inputConfig: ScanInputMockConfig{{
				path: "{path}",
			}},
			wantInventory: []*lockfile.Inventory{{{inv}
			}},
		}},'''

    print(
        template.format(name=name,
                        path=path,
                        inv=genInventory(path, inventory)))


beginFunc = False
beginExpectPackages = False
currentFuncName = ""
currentPath = ""

currentPkgs: list[InventoryItem] = []

allLines = sys.stdin.readlines()

for line in allLines:
    if beginFunc is False:
        match = re.match(f'func Test{startKey}_(.*?)\\(t .*?\\)', line)
        if match:
            currentFuncName = match.group(1).strip()
            beginFunc = True
        continue

    match = re.match(f'.*lockfile\\.{startKey}\\("(.*?)"\\)', line)
    if match:
        currentPath = match.group(1).strip()
        continue

    if beginExpectPackages is False:
        if line.strip().startswith("expectPackages(t"):
            beginExpectPackages = True
            continue

    if beginExpectPackages:
        nameMatch = re.match('.*Name:\s+"(.*)",', line)
        if nameMatch:
            currentPkgs.append(InventoryItem(nameMatch.group(1), ""))
            continue

        versionMatch = re.match('.*Version:\s+"(.*)",', line)
        if versionMatch:
            currentPkgs[-1].version = versionMatch.group(1)
            continue

        commitMatch = re.match('.*Commit:\s+"(.*)",', line)
        if commitMatch:
            currentPkgs[-1].commit = commitMatch.group(1)
            continue

        depGroupsMatch = re.match('.*DepGroups:\s+\\[\\]string{(.*?)},', line)
        if depGroupsMatch:
            currentPkgs[-1].depGroups = depGroupsMatch.group(1).split(",")
            continue

    if line.rstrip() == "}":
        beginFunc = False
        beginExpectPackages = False
        outputValue(currentPath.strip(), currentFuncName.strip(), currentPkgs)
        currentPkgs.clear()
