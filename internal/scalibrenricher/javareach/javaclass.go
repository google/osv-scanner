// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package javareach

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var (
	// BinaryBaseTypes comes from https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3
	BinaryBaseTypes = []string{
		"B",
		"C",
		"D",
		"F",
		"I",
		"J",
		"L",
		"S",
		"Z",
	}

	// StandardLibraryPrefixes defines the prefixes of standard library classes.
	StandardLibraryPrefixes = []string{
		"java/",
		"javax/",
		"jdk/",
		"sun/",
		"org/ietf/",
		"org/omg/",
		"org/w3c/",
		"org/xml/",
	}
)

// ClassFile struct represents the overall structure of a Java class file.
// This only contains the fields we care about for reachability analysis.
type ClassFile struct {
	Magic             uint32
	MinorVersion      uint16
	MajorVersion      uint16
	ConstantPoolCount uint16
	ConstantPool      []ConstantPoolInfo
	AccessFlags       uint16
	ThisClass         uint16
}

// ConstantPoolInfo interface represents the base type for all constant pool entries.
type ConstantPoolInfo interface {
	Type() ConstantKind
}

// ConstantKind is the type of a constant pool entry.
type ConstantKind uint8

// ConstantKind values are defined in JAR constant pool entries.
const (
	ConstantKindUtf8               ConstantKind = 1
	ConstantKindInteger            ConstantKind = 3
	ConstantKindFloat              ConstantKind = 4
	ConstantKindLong               ConstantKind = 5
	ConstantKindDouble             ConstantKind = 6
	ConstantKindClass              ConstantKind = 7
	ConstantKindString             ConstantKind = 8
	ConstantKindFieldref           ConstantKind = 9
	ConstantKindMethodref          ConstantKind = 10
	ConstantKindInterfaceMethodref ConstantKind = 11
	ConstantKindNameAndType        ConstantKind = 12
	ConstantKindMethodHandle       ConstantKind = 15
	ConstantKindMethodType         ConstantKind = 16
	ConstantKindDynamic            ConstantKind = 17
	ConstantKindInvokeDynamic      ConstantKind = 18
	ConstantKindModule             ConstantKind = 19
	ConstantKindPackage            ConstantKind = 20

	// This is not a real Java class constant kind.
	// We use this to implement long and double constants taking up two entries
	// in the constant pool, as well as the constant pool being 1-indexed.
	//
	// From https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html#jvms-4.4.5
	// All 8-byte constants take up two entries in the constant_pool table of
	// the class file. If a CONSTANT_Long_info or CONSTANT_Double_info structure
	// is the entry at index n in the constant_pool table, then the next usable
	// entry in the table is located at index n+2. The constant_pool index n+1
	// must be valid but is considered unusable.
	ConstantKindPlaceholder ConstantKind = 255
)

type (
	// ConstantClass represents a class constant pool entry.
	ConstantClass struct {
		NameIndex uint16
	}
	// ConstantFieldref represents a field reference constant pool entry.
	ConstantFieldref struct {
		ClassIndex       uint16
		NameAndTypeIndex uint16
	}
	// ConstantMethodref represents a method reference constant pool entry.
	ConstantMethodref struct {
		ClassIndex       uint16
		NameAndTypeIndex uint16
	}
	// ConstantInterfaceMethodref represents an interface method reference constant pool entry.
	ConstantInterfaceMethodref struct {
		ClassIndex       uint16
		NameAndTypeIndex uint16
	}
	// ConstantString represents a string constant pool entry.
	ConstantString struct {
		StringIndex uint16
	}
	// ConstantInteger represents an integer constant pool entry.
	ConstantInteger struct {
		Bytes int32
	}
	// ConstantFloat represents a float constant pool entry.
	ConstantFloat struct {
		Bytes float32
	}
	// ConstantLong represents a long constant pool entry.
	ConstantLong struct {
		Bytes int64
	}
	// ConstantDouble represents a double constant pool entry.
	ConstantDouble struct {
		Bytes float64
	}
	// ConstantNameAndType represents a name and type constant pool entry.
	ConstantNameAndType struct {
		NameIndex       uint16
		DescriptorIndex uint16
	}
	// ConstantUtf8 represents a UTF-8 string constant pool entry.
	ConstantUtf8 struct {
		Length uint16
		Bytes  []byte
	}
	// ConstantMethodHandle represents a method handle constant pool entry.
	ConstantMethodHandle struct {
		ReferenceKind  uint8
		ReferenceIndex uint16
	}
	// ConstantMethodType represents a method type constant pool entry.
	ConstantMethodType struct {
		DescriptorIndex uint16
	}
	// ConstantInvokeDynamic represents an invoke dynamic constant pool entry.
	ConstantInvokeDynamic struct {
		BootstrapMethodAttrIndex uint16
		NameAndTypeIndex         uint16
	}
	// ConstantModule represents a module constant pool entry.
	ConstantModule struct {
		NameIndex uint16
	}
	// ConstantPackage represents a package constant pool entry.
	ConstantPackage struct {
		NameIndex uint16
	}
	// ConstantDynamic represents a dynamic constant pool entry.
	ConstantDynamic struct {
		BootstrapMethodAttrIndex uint16
		NameAndTypeIndex         uint16
	}
	// ConstantPlaceholder is a placeholder constant pool entry.
	ConstantPlaceholder struct{}
)

// Type returns the ConstantKind for ConstantClass.
func (c ConstantClass) Type() ConstantKind { return ConstantKindClass }

// Type returns the ConstantKind for ConstantFieldref.
func (c ConstantFieldref) Type() ConstantKind { return ConstantKindFieldref }

// Type returns the ConstantKind for ConstantMethodref.
func (c ConstantMethodref) Type() ConstantKind { return ConstantKindMethodref }

// Type returns the ConstantKind for ConstantInterfaceMethodref.
func (c ConstantInterfaceMethodref) Type() ConstantKind { return ConstantKindInterfaceMethodref }

// Type returns the ConstantKind for ConstantString.
func (c ConstantString) Type() ConstantKind { return ConstantKindString }

// Type returns the ConstantKind for ConstantInteger.
func (c ConstantInteger) Type() ConstantKind { return ConstantKindInteger }

// Type returns the ConstantKind for ConstantFloat.
func (c ConstantFloat) Type() ConstantKind { return ConstantKindFloat }

// Type returns the ConstantKind for ConstantLong.
func (c ConstantLong) Type() ConstantKind { return ConstantKindLong }

// Type returns the ConstantKind for ConstantDouble.
func (c ConstantDouble) Type() ConstantKind { return ConstantKindDouble }

// Type returns the ConstantKind for ConstantNameAndType.
func (c ConstantNameAndType) Type() ConstantKind { return ConstantKindNameAndType }

// Type returns the ConstantKind for ConstantUtf8.
func (c ConstantUtf8) Type() ConstantKind { return ConstantKindUtf8 }

// Type returns the ConstantKind for ConstantMethodHandle.
func (c ConstantMethodHandle) Type() ConstantKind { return ConstantKindMethodHandle }

// Type returns the ConstantKind for ConstantMethodType.
func (c ConstantMethodType) Type() ConstantKind { return ConstantKindMethodType }

// Type returns the ConstantKind for ConstantInvokeDynamic.
func (c ConstantInvokeDynamic) Type() ConstantKind { return ConstantKindInvokeDynamic }

// Type returns the ConstantKind for ConstantModule.
func (c ConstantModule) Type() ConstantKind { return ConstantKindModule }

// Type returns the ConstantKind for ConstantPackage.
func (c ConstantPackage) Type() ConstantKind { return ConstantKindPackage }

// Type returns the ConstantKind for ConstantDynamic.
func (c ConstantDynamic) Type() ConstantKind { return ConstantKindDynamic }

// Type returns the ConstantKind for ConstantPlaceholder.
func (c ConstantPlaceholder) Type() ConstantKind { return ConstantKindPlaceholder }

// ParseClass parses a Java class file from a reader.
func ParseClass(r io.Reader) (*ClassFile, error) {
	var cf ClassFile
	err := binary.Read(r, binary.BigEndian, &cf.Magic)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &cf.MinorVersion)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &cf.MajorVersion)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &cf.ConstantPoolCount)
	if err != nil {
		return nil, err
	}

	// Add a dummy constant so that entries are 1-indexed per the Java spec.
	cf.ConstantPool = append(cf.ConstantPool, &ConstantPlaceholder{})

	// The value of the constant_pool_count item is equal to the number of
	// entries in the constant_pool table plus one.
	for i := 0; i < int(cf.ConstantPoolCount-1); i++ {
		var kind ConstantKind
		err := binary.Read(r, binary.BigEndian, &kind)
		if err != nil {
			return nil, err
		}

		var cp ConstantPoolInfo

		switch kind {
		case ConstantKindUtf8:
			constant := &ConstantUtf8{}
			err := binary.Read(r, binary.BigEndian, &constant.Length)
			if err != nil {
				return nil, err
			}

			const maxConstantLength = 32 * 1024
			if constant.Length > maxConstantLength {
				return nil, fmt.Errorf("constant size too large (%d)", constant.Length)
			}

			constant.Bytes = make([]byte, constant.Length)
			_, err = r.Read(constant.Bytes)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindInteger:
			constant := &ConstantInteger{}
			err := binary.Read(r, binary.BigEndian, &constant.Bytes)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindFloat:
			constant := &ConstantFloat{}
			err := binary.Read(r, binary.BigEndian, &constant.Bytes)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindLong:
			constant := &ConstantLong{}
			err := binary.Read(r, binary.BigEndian, &constant.Bytes)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindDouble:
			constant := &ConstantDouble{}
			err := binary.Read(r, binary.BigEndian, &constant.Bytes)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindClass:
			constant := &ConstantClass{}
			err := binary.Read(r, binary.BigEndian, &constant.NameIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindString:
			constant := &ConstantString{}
			err := binary.Read(r, binary.BigEndian, &constant.StringIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindFieldref:
			constant := &ConstantFieldref{}
			err := binary.Read(r, binary.BigEndian, &constant.ClassIndex)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.NameAndTypeIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindMethodref:
			constant := &ConstantMethodref{}
			err := binary.Read(r, binary.BigEndian, &constant.ClassIndex)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.NameAndTypeIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindInterfaceMethodref:
			constant := &ConstantInterfaceMethodref{}
			err := binary.Read(r, binary.BigEndian, &constant.ClassIndex)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.NameAndTypeIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindNameAndType:
			constant := &ConstantNameAndType{}
			err := binary.Read(r, binary.BigEndian, &constant.NameIndex)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.DescriptorIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindMethodHandle:
			constant := &ConstantMethodHandle{}
			err := binary.Read(r, binary.BigEndian, &constant.ReferenceKind)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.ReferenceIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindMethodType:
			constant := &ConstantMethodType{}
			err := binary.Read(r, binary.BigEndian, &constant.DescriptorIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindDynamic:
			constant := &ConstantDynamic{}
			err := binary.Read(r, binary.BigEndian, &constant.BootstrapMethodAttrIndex)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.NameAndTypeIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindInvokeDynamic:
			constant := &ConstantInvokeDynamic{}
			err := binary.Read(r, binary.BigEndian, &constant.BootstrapMethodAttrIndex)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &constant.NameAndTypeIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindModule:
			constant := &ConstantModule{}
			err := binary.Read(r, binary.BigEndian, &constant.NameIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		case ConstantKindPackage:
			constant := &ConstantPackage{}
			err := binary.Read(r, binary.BigEndian, &constant.NameIndex)
			if err != nil {
				return nil, err
			}
			cp = constant
		default:
			return nil, fmt.Errorf("invalid cp_info type %d at index %d", kind, i+1)
		}

		cf.ConstantPool = append(cf.ConstantPool, cp)

		if cp.Type() == ConstantKindDouble || cp.Type() == ConstantKindLong {
			// 8-byte values take up 2 constant pool entries.
			cf.ConstantPool = append(cf.ConstantPool, &ConstantPlaceholder{})
			i++
		}
	}

	err = binary.Read(r, binary.BigEndian, &cf.AccessFlags)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, &cf.ThisClass)
	if err != nil {
		return nil, err
	}

	return &cf, nil
}

func (cf *ClassFile) checkIndex(idx int) error {
	// From https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html#jvms-4.4.1
	//
	// A constant_pool index is considered valid if it is greater than
	// zero and less than constant_pool_count, with the exception for
	// constants of type long and double noted in §4.4.5.
	if idx == 0 || idx >= len(cf.ConstantPool) {
		return fmt.Errorf("invalid index %d", idx)
	}

	return nil
}

// ConstantPoolMethodref returns the class, method, and descriptor for a method reference at the
// given index.
func (cf *ClassFile) ConstantPoolMethodref(idx int) (class string, method string, descriptor string, err error) {
	err = cf.checkIndex(idx)
	if err != nil {
		return class, method, descriptor, err
	}

	if cf.ConstantPool[idx].Type() != ConstantKindMethodref {
		err = errors.New("constant pool idx does not point to a method ref")
		return class, method, descriptor, err
	}

	methodRef := cf.ConstantPool[idx].(*ConstantMethodref)
	class, err = cf.ConstantPoolClass(int(methodRef.ClassIndex))
	if err != nil {
		return class, method, descriptor, err
	}

	err = cf.checkIndex(int(methodRef.NameAndTypeIndex))
	if err != nil {
		return class, method, descriptor, err
	}

	nameAndType, ok := cf.ConstantPool[methodRef.NameAndTypeIndex].(*ConstantNameAndType)
	if !ok {
		err = errors.New("invalid constant name and type")
		return class, method, descriptor, err
	}
	method, err = cf.ConstantPoolUtf8(int(nameAndType.NameIndex))
	if err != nil {
		return class, method, descriptor, err
	}
	descriptor, err = cf.ConstantPoolUtf8(int(nameAndType.DescriptorIndex))

	return class, method, descriptor, err
}

// ConstantPoolClass returns the class name at the given index.
func (cf *ClassFile) ConstantPoolClass(idx int) (string, error) {
	if err := cf.checkIndex(idx); err != nil {
		return "", err
	}
	if cf.ConstantPool[idx].Type() != ConstantKindClass {
		return "", errors.New("constant pool idx does not point to a class")
	}

	classInfo := cf.ConstantPool[idx].(*ConstantClass)

	return cf.ConstantPoolUtf8(int(classInfo.NameIndex))
}

// ConstantPoolUtf8 returns the UTF-8 string at the given index.
func (cf *ClassFile) ConstantPoolUtf8(idx int) (string, error) {
	if err := cf.checkIndex(idx); err != nil {
		return "", err
	}
	if cf.ConstantPool[idx].Type() != ConstantKindUtf8 {
		return "", errors.New("constant pool idx does not point to a utf8 string")
	}

	data := cf.ConstantPool[idx].(*ConstantUtf8)
	if !utf8.Valid(data.Bytes) {
		return "", errors.New("invalid utf8 bytes")
	}

	return string(data.Bytes), nil
}

// IsStdLib returns true if the class is a standard library class.
func IsStdLib(class string) bool {
	for _, prefix := range StandardLibraryPrefixes {
		if strings.HasPrefix(class, prefix) {
			return true
		}
	}

	return false
}
