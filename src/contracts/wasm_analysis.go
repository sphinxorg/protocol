// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"fmt"
)

// WASMAnalysis is a conservative, deterministic upper bound for one contract
// invocation. The validator accepts only loop-free, direct-host-call modules,
// therefore this bound cannot be bypassed by a program at runtime.
type WASMAnalysis struct {
	Operations    uint64
	HostCalls     uint64
	StorageReads  uint64
	StorageWrites uint64
	EventBytes    uint64
	Transfers     uint64
}

// AnalyzeWASM parses the standard WASM binary sections used by the restricted
// runtime. It rejects floating point, loops, indirect/internal calls, memory
// growth, bulk/SIMD instructions, and unknown opcodes. This is intentionally a
// small deterministic WASM profile, not a general browser/WASI validator.
func AnalyzeWASM(code []byte) (WASMAnalysis, error) {
	if !IsWASM(code) {
		return WASMAnalysis{}, fmt.Errorf("invalid WASM magic/version")
	}
	p := wasmParser{b: code[8:]}
	var imports []string
	var result WASMAnalysis
	for len(p.b) > 0 {
		id, err := p.byte()
		if err != nil {
			return result, err
		}
		n, err := p.u32()
		if err != nil || uint64(n) > uint64(len(p.b)) {
			return result, fmt.Errorf("malformed WASM section")
		}
		section := wasmParser{b: p.take(int(n))}
		parsed := false
		switch id {
		case 2:
			parsed = true
			imports, err = parseImports(&section)
		case 10:
			parsed = true
			err = parseCode(&section, imports, &result)
		}
		if err != nil {
			return result, err
		}
		if parsed && len(section.b) != 0 {
			return result, fmt.Errorf("malformed WASM section %d", id)
		}
	}
	if result.Operations == 0 {
		return result, fmt.Errorf("WASM has no executable instructions")
	}
	return result, nil
}

type wasmParser struct{ b []byte }

func (p *wasmParser) byte() (byte, error) {
	if len(p.b) == 0 {
		return 0, fmt.Errorf("truncated WASM")
	}
	x := p.b[0]
	p.b = p.b[1:]
	return x, nil
}
func (p *wasmParser) take(n int) []byte { x := p.b[:n]; p.b = p.b[n:]; return x }
func (p *wasmParser) u32() (uint32, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		x, e := p.byte()
		if e != nil {
			return 0, e
		}
		v |= uint32(x&127) << uint(7*i)
		if x&128 == 0 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("invalid WASM LEB128")
}
func (p *wasmParser) leb() error {
	for i := 0; i < 10; i++ {
		x, e := p.byte()
		if e != nil {
			return e
		}
		if x&128 == 0 {
			return nil
		}
	}
	return fmt.Errorf("invalid WASM LEB128")
}
func (p *wasmParser) name() error {
	n, e := p.u32()
	if e != nil || uint64(n) > uint64(len(p.b)) {
		return fmt.Errorf("invalid WASM name")
	}
	p.take(int(n))
	return nil
}
func (p *wasmParser) readName() (string, error) {
	n, err := p.u32()
	if err != nil || uint64(n) > uint64(len(p.b)) {
		return "", fmt.Errorf("invalid WASM name")
	}
	return string(p.take(int(n))), nil
}

func parseImports(p *wasmParser) ([]string, error) {
	n, e := p.u32()
	if e != nil {
		return nil, e
	}
	var funcs []string
	for ; n > 0; n-- {
		if e = p.name(); e != nil {
			return nil, e
		}
		name, e := p.readName()
		if e != nil {
			return nil, e
		}
		k, e := p.byte()
		if e != nil {
			return nil, e
		}
		switch k {
		case 0:
			if _, e = p.u32(); e != nil {
				return nil, e
			}
			funcs = append(funcs, name)
		case 1:
			e = skipTable(p)
		case 2:
			e = skipMemory(p)
		case 3:
			_, e = p.byte()
			if e == nil {
				_, e = p.byte()
			}
		default:
			return nil, fmt.Errorf("unknown WASM import kind")
		}
		if e != nil {
			return nil, e
		}
	}
	return funcs, nil
}
func skipLimits(p *wasmParser) error {
	f, e := p.byte()
	if e != nil {
		return e
	}
	if _, e = p.u32(); e != nil {
		return e
	}
	if f == 1 {
		_, e = p.u32()
	}
	return e
}
func skipTable(p *wasmParser) error {
	if _, e := p.byte(); e != nil {
		return e
	}
	return skipLimits(p)
}
func skipMemory(p *wasmParser) error { return skipLimits(p) }

func parseCode(p *wasmParser, imports []string, a *WASMAnalysis) error {
	n, e := p.u32()
	if e != nil {
		return e
	}
	for ; n > 0; n-- {
		size, e := p.u32()
		if e != nil || uint64(size) > uint64(len(p.b)) {
			return fmt.Errorf("invalid WASM function body")
		}
		body := wasmParser{b: p.take(int(size))}
		locals, e := body.u32()
		if e != nil {
			return e
		}
		for ; locals > 0; locals-- {
			if _, e = body.u32(); e != nil {
				return e
			}
			if _, e = body.byte(); e != nil {
				return e
			}
		}
		if e = parseInstructions(&body, imports, a); e != nil {
			return e
		}
		if len(body.b) != 0 {
			return fmt.Errorf("trailing WASM function bytes")
		}
	}
	return nil
}
func parseInstructions(p *wasmParser, imports []string, a *WASMAnalysis) error {
	depth := 0
	for {
		op, e := p.byte()
		if e != nil {
			return e
		}
		a.Operations++
		switch {
		case op == 0x0b:
			if depth == 0 {
				return nil
			}
			depth--
		case op == 0x02 || op == 0x04:
			if e = p.leb(); e != nil {
				return e
			}
			depth++
		case op == 0x03:
			return fmt.Errorf("WASM loops are not supported")
		case op == 0x0c || op == 0x0d || op == 0x10:
			idx, e := p.u32()
			if e != nil {
				return e
			}
			if op == 0x10 {
				if idx >= uint32(len(imports)) {
					return fmt.Errorf("WASM internal calls are not supported")
				}
				a.HostCalls++
				switch imports[idx] {
				case "storage_get", "calldata_word", "caller", "transferred_value", "block_height":
					a.StorageReads++
				case "storage_set":
					a.StorageWrites++
				case "emit_event":
					a.EventBytes += 16
				case "transfer":
					a.Transfers++
				}
			}
		case op == 0x0e:
			n, e := p.u32()
			if e != nil {
				return e
			}
			for ; n > 0; n-- {
				if _, e = p.u32(); e != nil {
					return e
				}
			}
			if _, e = p.u32(); e != nil {
				return e
			}
		case op == 0x11 || op == 0x40 || op == 0xfc || op == 0xfd:
			return fmt.Errorf("unsupported non-deterministic or unmetered WASM instruction 0x%x", op)
		case op >= 0x20 && op <= 0x24:
			if _, e = p.u32(); e != nil {
				return e
			}
		case op >= 0x28 && op <= 0x3e:
			if _, e = p.u32(); e != nil {
				return e
			}
			if _, e = p.u32(); e != nil {
				return e
			}
		case op == 0x3f:
			if _, e = p.byte(); e != nil {
				return e
			}
		case op == 0x41 || op == 0x42:
			if e = p.leb(); e != nil {
				return e
			}
		case op == 0x43 || op == 0x44 || (op >= 0x5b && op <= 0xa6) || (op >= 0xa8 && op <= 0xab) || (op >= 0xae && op <= 0xbf) || op >= 0xd0:
			return fmt.Errorf("floating-point or unsupported WASM instruction 0x%x", op)
		case op <= 0x1b || (op >= 0x45 && op <= 0x5a) || (op >= 0xa7 && op <= 0xad):
		default:
			return fmt.Errorf("unsupported WASM instruction 0x%x", op)
		}
	}
}
