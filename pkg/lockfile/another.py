"""

Helper script, remember to remove later!!
"""

import sys
import re
from dataclasses import dataclass

filename = sys.argv[1]

file = open(filename)
allLines = file.readlines()

output = ""
extractorName = ""
extractorFileName = ""

insertLine = """
// Name of the extractor
func (e [-extractname]) Name() string { return "go/gomod" }

// Version of the extractor
func (e [-extractname]) Version() int { return 0 }

func (e [-extractname]) Requirements() Requirements {
	return Requirements{}
}
"""

insertLineTwo = """
func (e [-extractname]) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "[-extractFileName]"
}
"""

replaceLineThree = "func (e [-extractname]) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {"

insertLineFour = """

// ToPURL converts an inventory created by this extractor into a PURL.
func (e [-extractname]) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.--,
		Name:    i.Name,
		Version: i.Version,

	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e [-extractname]) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e [-extractname]) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case [-extractname]:
		return string(--), nil
	default:
		return "", ErrWrongExtractor
	}
}
"""

removeNextLines = 0

for line in allLines:
    matchOne = re.match("type ([a-zA-Z]+Extractor) struct{}", line)
    if matchOne:
        extractorName = matchOne.group(1)
        output += line
        output += insertLine.replace("[-extractname]", extractorName)
        continue

    matchTwo = re.match("func .* ShouldExtract\\(path.* bool", line)
    if matchTwo:
        continue

    matchThree = re.match('.*return filepath\\.Base\\(path\\) == \\"(.*?)\\"', line)

    if matchThree:
        print("YOOO")
        extractorFileName = matchThree.group(1)
        output += insertLineTwo.replace("[-extractname]", extractorName).replace("[-extractFileName]", extractorFileName)
        removeNextLines = 1
        continue

    matchFour = re.match('func \\(.* Extract\\(f DepFile\\)', line)
    if matchFour:
        output += replaceLineThree.replace("[-extractname]", extractorName)
        continue

    matchFive = re.match('var _ Extractor = ', line)
    if matchFive:
        output += insertLineFour.replace("[-extractname]", extractorName)
        output += line
        continue

    if removeNextLines > 0:
        removeNextLines -= 1
    else:
      output += line.replace("(f)", "(input.Reader)").replace("f.Path()", "input.Path").replace("PackageDetails", "*Inventory")


f = open(filename, "w")
f.write(output)
f.close()
# print(output)
# expectCommit = True
# expectDepGroups = True
# startKey = "ParsePoetryLock"


# @dataclass
# class InventoryItem:
#     """Class for keeping track of an item in inventory."""
#     name: str
#     version: str
#     commit: str = ""
#     depGroups: list[str] = None


# def genInventory(path, valueList: list[InventoryItem]) -> str:
#     buildStr = ""
#     for i in valueList:
#         current = f"""
#         {{
#             Name:      "{i.name}",
#             Version:   "{i.version}",
#             Locations: []string{{"{path}"}},
# """
#         if expectCommit:
#             current += f'SourceCode: &lockfile.SourceCodeIdentifier{{\nCommit: "{i.commit}",\n}},\n'

#         if expectDepGroups:
#             current += f"Metadata: lockfile.DepGroupMetadata{{\nDepGroupVals: []string{{{', '.join(i.depGroups or [])}}},\n}},\n"

#         current += '},'
#         buildStr += current
#     return buildStr


# def outputValue(path, funcName, inventory: list[InventoryItem]):
#     name = re.sub(r'(?<!^)(?=[A-Z])', ' ', funcName).lower()

#     template = '''{{
# 			name: "{name}",
# 			inputConfig: ScanInputMockConfig{{
# 				path: "{path}",
# 			}},
# 			wantInventory: []*lockfile.Inventory{{{inv}
# 			}},
# 		}},'''

#     print(
#         template.format(name=name,
#                         path=path,
#                         inv=genInventory(path, inventory)))


# beginFunc = False
# beginExpectPackages = False
# currentFuncName = ""
# currentPath = ""

# currentPkgs: list[InventoryItem] = []

# allLines = sys.stdin.readlines()

# for line in allLines:
#     if beginFunc is False:
#         match = re.match(f'func Test{startKey}_(.*?)\\(t .*?\\)', line)
#         if match:
#             currentFuncName = match.group(1).strip()
#             beginFunc = True
#         continue

#     match = re.match(f'.*lockfile\\.{startKey}\\("(.*?)"\\)', line)
#     if match:
#         currentPath = match.group(1).strip()
#         continue

#     if beginExpectPackages is False:
#         if line.strip().startswith("expectPackages(t"):
#             beginExpectPackages = True
#             continue

#     if beginExpectPackages:
#         nameMatch = re.match('.*Name:\s+"(.*)",', line)
#         if nameMatch:
#             currentPkgs.append(InventoryItem(nameMatch.group(1), ""))
#             continue

#         versionMatch = re.match('.*Version:\s+"(.*)",', line)
#         if versionMatch:
#             currentPkgs[-1].version = versionMatch.group(1)
#             continue

#         commitMatch = re.match('.*Commit:\s+"(.*)",', line)
#         if commitMatch:
#             currentPkgs[-1].commit = commitMatch.group(1)
#             continue

#         depGroupsMatch = re.match('.*DepGroups:\s+\\[\\]string{(.*?)},', line)
#         if depGroupsMatch:
#             currentPkgs[-1].depGroups = depGroupsMatch.group(1).split(",")
#             continue

#     if line.rstrip() == "}":
#         beginFunc = False
#         beginExpectPackages = False
#         outputValue(currentPath.strip(), currentFuncName.strip(), currentPkgs)
#         currentPkgs.clear()
