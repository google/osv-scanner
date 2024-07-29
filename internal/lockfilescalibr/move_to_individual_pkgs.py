"""

Helper script, remember to remove later!!
"""
from pathlib import Path
import sys
import re
import shutil
import os
from dataclasses import dataclass

filename = sys.argv[1]
testFilename = Path(filename).stem + "_test.go"

file = open(filename)
allLines = file.readlines()
file.close()

file = open(testFilename)
allLinesTest = file.readlines()
file.close()

structName = ""
extName = ""
ecosystemName = ""

for line in allLines:
  mat = re.match(r'func \(e ([a-zA-Z]+?)\) Name\(\) string { return "([a-z/]+)" }', line)
  if mat:
    structName = mat.group(1)
    extName = mat.group(2)

  mat2 = re.match(r".*string\((.*Ecosystem)\)", line)
  if mat2:
    ecosystemName = mat2.group(1)


a = input(f"Check: {structName} -- {extName} -- {ecosystemName}\n")
if not os.path.isdir(f"fixtures/{a}"):
  print("Not a dir, exiting...")
  exit()

filePath = "language/" + extName + "/extractor.go"
filePathTest = "language/" + extName + "/extractor_test.go"

Path(filePath).parent.mkdir(parents=True, exist_ok=True)

pkgName = extName.split("/")[-1]

baseOutput = ""

replaceFunction = False

for line in allLines:
  if replaceFunction:
    if line.rstrip() == "}":
      replaceFunction = False
    else:
      continue

  line = line.replace(structName, "Extractor")
  line = line.replace("package lockfilescalibr", f'package {pkgName}')
  line = line.replace("Ecosystem = ", "string = ")
  # line = re.sub(r"string\((.*Ecosystem)\)", r"\1", line)

  if 'Ecosystem(i *extractor.Inventory)' in line:
    baseOutput += line
    baseOutput += "return " + ecosystemName + ", nil\n"
    replaceFunction = True
    continue

  baseOutput += line

# print(baseOutput)

f = open(filePath, "w")
f.write(baseOutput)
f.close()

baseOutputTest = ""

for line in allLinesTest:
  if replaceFunction:
    if line.rstrip() == "}":
      replaceFunction = False
    else:
      continue

  if line.strip() == '"github.com/google/osv-scanner/internal/lockfilescalibr"':
    continue

  if line.strip() == '"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"':
    baseOutputTest += line
    print("YOYOYOOYO")
    baseOutputTest += f'	"github.com/google/osv-scanner/internal/lockfilescalibr/language/{extName}"\n'
    continue

  line = line.replace("fixtures/cargo/", "testdata/")
  line = line.replace("package lockfilescalibr", f'package {pkgName}')
  line = line.replace("Ecosystem = ", "string = ")
  line = line.replace(f"lockfilescalibr.{structName}{{}}", f"{pkgName}.Extractor{{}}")
  line = line.replace(structName, "Extractor")

  baseOutputTest += line


f = open(filePathTest, "w")
f.write(baseOutputTest)
f.close()

testdataPath = Path("language/" + extName + "/testdata")
testdataPath.mkdir(parents=True, exist_ok=True)


shutil.copytree(f"fixtures/{a}", testdataPath, dirs_exist_ok=True)
