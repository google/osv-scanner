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

for file in files:
  extName = ""
  extType = ""
  extFileName = ""
  text = open(file, "r").readlines()
  for line in text:
    if line.startswith('package '):
      extType = line.strip().removeprefix('package ')
      continue

    mat = re.match(r'func \(e ([a-zA-Z]+?)\) Name\(\) string { return "([a-z/]+)" }', line)
    if mat:
      extName = mat.group(2)
      # extType = mat.group(1)
      continue

    mat2 = re.match(r'.*return filepath.Base\(path\) == "(.+)"$', line)
    if mat2:
      extFileName = mat2.group(1)

  print(f'"{extFileName}": "{extName}",')
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
