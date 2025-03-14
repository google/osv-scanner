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

type ConstantKind uint8

const (
	ConstantKindUtf8               ConstantKind = 1
	ConstantKindInteger                         = 3
	ConstantKindFloat                           = 4
	ConstantKindLong                            = 5
	ConstantKindDouble                          = 6
	ConstantKindClass                           = 7
	ConstantKindString                          = 8
	ConstantKindFieldref                        = 9
	ConstantKindMethodref                       = 10
	ConstantKindInterfaceMethodref              = 11
	ConstantKindNameAndType                     = 12
	ConstantKindMethodHandle                    = 15
	ConstantKindMethodType                      = 16
	ConstantKindDynamic                         = 17
	ConstantKindInvokeDynamic                   = 18
	ConstantKindModule                          = 19
	ConstantKindPackage                         = 20

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
	ConstantKindPlaceholder = 255
)

// ConstantPool entries
type (
	ConstantClass struct {
		NameIndex uint16
	}
	ConstantFieldref struct {
		ClassIndex       uint16
		NameAndTypeIndex uint16
	}
	ConstantMethodref struct {
		ClassIndex       uint16
		NameAndTypeIndex uint16
	}
	ConstantInterfaceMethodref struct {
		ClassIndex       uint16
		NameAndTypeIndex uint16
	}
	ConstantString struct {
		StringIndex uint16
	}
	ConstantInteger struct {
		Bytes int32
	}
	ConstantFloat struct {
		Bytes float32
	}
	ConstantLong struct {
		Bytes int64
	}
	ConstantDouble struct {
		Bytes float64
	}
	ConstantNameAndType struct {
		NameIndex       uint16
		DescriptorIndex uint16
	}
	ConstantUtf8 struct {
		Length uint16
		Bytes  []byte
	}
	ConstantMethodHandle struct {
		ReferenceKind  uint8
		ReferenceIndex uint16
	}
	ConstantMethodType struct {
		DescriptorIndex uint16
	}
	ConstantInvokeDynamic struct {
		BootstrapMethodAttrIndex uint16
		NameAndTypeIndex         uint16
	}
	ConstantModule struct {
		NameIndex uint16
	}
	ConstantPackage struct {
		NameIndex uint16
	}
	ConstantDynamic struct {
		BootstrapMethodAttrIndex uint16
		NameAndTypeIndex         uint16
	}
	ConstantPlaceholder struct{}
)

// Type methods for ConstantPoolInfo implementations
func (c ConstantClass) Type() ConstantKind              { return ConstantKindClass }
func (c ConstantFieldref) Type() ConstantKind           { return ConstantKindFieldref }
func (c ConstantMethodref) Type() ConstantKind          { return ConstantKindMethodref }
func (c ConstantInterfaceMethodref) Type() ConstantKind { return ConstantKindInterfaceMethodref }
func (c ConstantString) Type() ConstantKind             { return ConstantKindString }
func (c ConstantInteger) Type() ConstantKind            { return ConstantKindInteger }
func (c ConstantFloat) Type() ConstantKind              { return ConstantKindFloat }
func (c ConstantLong) Type() ConstantKind               { return ConstantKindLong }
func (c ConstantDouble) Type() ConstantKind             { return ConstantKindDouble }
func (c ConstantNameAndType) Type() ConstantKind        { return ConstantKindNameAndType }
func (c ConstantUtf8) Type() ConstantKind               { return ConstantKindUtf8 }
func (c ConstantMethodHandle) Type() ConstantKind       { return ConstantKindMethodHandle }
func (c ConstantMethodType) Type() ConstantKind         { return ConstantKindMethodType }
func (c ConstantInvokeDynamic) Type() ConstantKind      { return ConstantKindInvokeDynamic }
func (c ConstantModule) Type() ConstantKind             { return ConstantKindModule }
func (c ConstantPackage) Type() ConstantKind            { return ConstantKindPackage }
func (c ConstantDynamic) Type() ConstantKind            { return ConstantKindDynamic }
func (c ConstantPlaceholder) Type() ConstantKind        { return ConstantKindPlaceholder }

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
			i += 1
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

func (cf *ClassFile) ConstantPoolMethodref(idx int) (class string, method string, descriptor string, err error) {
	err = cf.checkIndex(idx)
	if err != nil {
		return
	}

	if cf.ConstantPool[idx].Type() != ConstantKindMethodref {
		err = errors.New("constant pool idx does not point to a method ref")
		return
	}

	methodRef := cf.ConstantPool[idx].(*ConstantMethodref)
	class, err = cf.ConstantPoolClass(int(methodRef.ClassIndex))
	if err != nil {
		return
	}

	err = cf.checkIndex(int(methodRef.NameAndTypeIndex))
	if err != nil {
		return
	}

	nameAndType, ok := cf.ConstantPool[methodRef.NameAndTypeIndex].(*ConstantNameAndType)
	if !ok {
		err = errors.New("invalid constant name and type")
		return
	}
	method, err = cf.ConstantPoolUtf8(int(nameAndType.NameIndex))
	if err != nil {
		return
	}
	descriptor, err = cf.ConstantPoolUtf8(int(nameAndType.DescriptorIndex))
	return
}

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

func IsStdLib(class string) bool {
	for _, prefix := range StandardLibraryPrefixes {
		if strings.HasPrefix(class, prefix) {
			return true
		}
	}

	return false
}
