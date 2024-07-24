"""

Helper script, remember to remove later!!
"""

import sys
import re


def genInventory(path, valueList: list) -> str:
    buildStr = ""
    for i in valueList:
        current = f"""
        {{
					Name:      "{i[0]}",
					Version:   "{i[1]}",
					Locations: []string{{"{path}"}},
				}},
"""
        buildStr += current
    return buildStr


def outputValue(path, funcName, inventory: list):
    name = re.sub(r'(?<!^)(?=[A-Z])', ' ', funcName).lower()

    template = '''{{
			name: "{name}",
			inputConfig: ScanInputMockConfig{{
				path: "{path}",
			}},
			wantInventory: []*lockfile.Inventory{{
            {inv}
			}},
		}},
    '''

    print(
        template.format(name=name,
                        path=path,
                        inv=genInventory(path, inventory)))


startKey = "ParseNpmLock"

beginFunc = False
beginExpectPackages = False
currentFuncName = ""
currentPath = ""

currentPkgs = []

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
            currentPkgs.append([nameMatch.group(1), ""])
            continue

        versionMatch = re.match('.*Version:\s+"(.*)",', line)
        if versionMatch:
            currentPkgs[-1][1] = versionMatch.group(1)
            continue

    if line.rstrip() == "}":
        beginFunc = False
        beginExpectPackages = False
        outputValue(currentPath.strip(), currentFuncName.strip(), currentPkgs)
        currentPkgs.clear()
