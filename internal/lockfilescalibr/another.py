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

func (e [-extractname]) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
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
