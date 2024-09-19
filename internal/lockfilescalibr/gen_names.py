"""

Helper script, remember to remove later!!
"""
from pathlib import Path
import sys
import re
import shutil
import os
import glob
from dataclasses import dataclass

files = glob.glob("./**/extractor.go", recursive=True)

oldEntryFileReq = ""
oldEntryExtract = ""
oldEntryEcosystem = ""
oldEntryLang = ""

fileReqTemplate = "// FileRequired returns true if the specified file matches {} lockfile patterns."
extractTemplate = "// Extract extracts packages from {} files passed through the scan input."
ecosystemTemplate = "// Ecosystem returns the OSV ecosystem ('{}') of the software extracted by this extractor."
extorTemplate = "// Extractor extracts {} packages from {} files."
pkgTemplate = "// Package {} extracts {} files."

output = ""

for file in files:
  preLineComment = False
  text = open(file, "r").readlines()
  pkgName = ""
  for line in text:
    if line.startswith('// '):
      preLineComment = True
      output += line
      continue

    if preLineComment:
      output += line
      preLineComment = False
      continue

    mat = re.match(r'^package (.*)$', line)
    if mat:
      pkgName = mat.group(1)
      newEntryExtract = input(f"{pkgName} Found Extract, writing: \n{pkgTemplate}\nWith '{oldEntryExtract}')\nEnter new: ")
      if newEntryExtract:
        oldEntryExtract = newEntryExtract
      output += pkgTemplate.format(pkgName, oldEntryExtract) + "\n" + line
      continue


    if line.startswith("type Extractor struct"):
      newEntryLang = input(f"{pkgName} Found Extractor struct, writing: \n{extorTemplate}\nWith '{oldEntryLang}')\nEnter new: ")
      if newEntryLang:
        oldEntryLang = newEntryLang
      newEntryExtract = input(f"Second ({oldEntryExtract}): ")
      if newEntryExtract:
        oldEntryExtract = newEntryExtract
      output += extorTemplate.format(oldEntryLang, oldEntryExtract) + "\n" + line
      continue

    mat = re.match(r'^(type|const) [A-Z]', line)
    if mat:
      ans = input(f"Found: \n{line}Add TODO? (Y/n)")
      if ans == "n":
        output += line
      else:
        output += "// TODO: Make Private\n" + line
      continue

    if line.startswith("func (e Extractor) Requirements()"):
      output += "// Requirements of the extractor\n" + line
      continue

    if line.startswith("func (e Extractor) FileRequired"):
      newEntryFileReq = input(f"{pkgName} Found FileReq, writing: \n{fileReqTemplate}\nWith '{oldEntryFileReq}')\nEnter new: ")
      if newEntryFileReq:
        oldEntryFileReq = newEntryFileReq
      output += fileReqTemplate.format(oldEntryFileReq) + "\n" + line
      continue

    if line.startswith("func (e Extractor) Extract"):
      newEntryExtract = input(f"{pkgName} Found Extract, writing: \n{extractTemplate}\nWith '{oldEntryExtract}')\nEnter new: ")
      if newEntryExtract:
        oldEntryExtract = newEntryExtract
      output += extractTemplate.format(oldEntryExtract) + "\n" + line
      continue

    if line.startswith("func (e Extractor) Ecosystem"):
      newEntryEcosystem = input(f"{pkgName} Found Ecosystem, writing: \n{ecosystemTemplate}\nWith '{oldEntryEcosystem}')\nEnter new: ")
      if newEntryEcosystem:
        oldEntryEcosystem = newEntryEcosystem
      output += ecosystemTemplate.format(oldEntryEcosystem) + "\n" + line
      continue



    output += line

  toWrite = open(file, "w")
  toWrite.write(output)
  output = ""
  # print(f'"{extFileName}": "{extName}",')
  # print(extName)
  # print(extType)
  # print(extFileName)
  # print()


# # filename = sys.argv[1]
# # testFileNames = glob.glob(Path(filename).stem+"*"+"_test.go")


# # testFilename = Path(filename).stem + "_test.go"

# file = open(filename)
# allLines = file.readlines()
# file.close()


# structName = ""
# extName = ""
# ecosystemName = ""

# for line in allLines:
#   mat = re.match(r'func \(e ([a-zA-Z]+?)\) Name\(\) string { return "([a-z/]+)" }', line)
#   if mat:
#     structName = mat.group(1)
#     extName = mat.group(2)

#   mat2 = re.match(r".*string\((.*Ecosystem)\)", line)
#   if mat2:
#     ecosystemName = mat2.group(1)


# fixturesFolderName = input(f"Check: {structName} -- {extName} -- {ecosystemName}\n")
# if not os.path.isdir(f"fixtures/{fixturesFolderName}"):
#   print("Not a dir, exiting...")
#   exit()

# filePath = "language/" + extName + "/extractor.go"

# Path(filePath).parent.mkdir(parents=True, exist_ok=True)

# pkgName = extName.split("/")[-1]

# baseOutput = ""

# replaceFunction = False

# for line in allLines:
#   if replaceFunction:
#     if line.rstrip() == "}":
#       replaceFunction = False
#     else:
#       continue

#   line = line.replace(structName, "Extractor")
#   line = line.replace("package lockfilescalibr", f'package {pkgName}')
#   line = line.replace("Ecosystem = ", "string = ")
#   # line = re.sub(r"string\((.*Ecosystem)\)", r"\1", line)

#   if 'Ecosystem(i *extractor.Inventory)' in line:
#     baseOutput += line
#     baseOutput += "	return " + ecosystemName + ", nil\n"
#     replaceFunction = True
#     continue

#   baseOutput += line

# # print(baseOutput)

# f = open(filePath, "w")
# f.write(baseOutput)
# f.close()

# def moveTestFile(testPath: str):
#   file = open(testPath)
#   allLinesTest = file.readlines()
#   file.close()
#   outputPathTest =  "language/" + extName + f"/extractor{testPath.removeprefix(Path(filename).stem)}"
#   # print(outputPathTest)
#   baseOutputTest = ""
#   replaceFunction = False

#   # filePathTest = "language/" + extName + "/extractor_test.go"
#   for line in allLinesTest:
#     if replaceFunction:
#       if line.rstrip() == "}":
#         replaceFunction = False
#       else:
#         continue

#     if line.strip() == '"github.com/google/osv-scanner/internal/lockfilescalibr"':
#       continue

#     if line.strip() == '"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"':
#       baseOutputTest += line
#       baseOutputTest += f'	"github.com/google/osv-scanner/internal/lockfilescalibr/language/{extName}"\n'
#       continue

#     line = line.replace(f"fixtures/{fixturesFolderName}/", "testdata/")
#     line = line.replace("package lockfilescalibr", f'package {pkgName}')
#     line = line.replace("Ecosystem = ", "string = ")
#     line = line.replace(f"lockfilescalibr.{structName}{{}}", f"{pkgName}.Extractor{{}}")
#     line = line.replace(structName, "Extractor")

#     baseOutputTest += line


#   f = open(outputPathTest, "w")
#   f.write(baseOutputTest)
#   f.close()

# for i in testFileNames:
#   moveTestFile(i)

# testdataPath = Path("language/" + extName + "/testdata")

# testdataPath.mkdir(parents=True, exist_ok=True)
# shutil.copytree(f"fixtures/{fixturesFolderName}", testdataPath, dirs_exist_ok=True)
