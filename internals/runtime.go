package internals

/*
   slightly adapted from hooka loader

   i could have just yoinked the code and used it like that but i plan to
   do different things in the future, which will need me to implement things
   differently, but this is an excellent base if you want to get started
   or use a more stable loader :)


*/

import (
	"encoding/binary"
	"errors"

	"github.com/Binject/debug/pe"
)

func rva2offset(pe *pe.File, rva uint32) uint32 {
    for _, hdr := range pe.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

func HashedSyscall(callid uint16, argh ...uintptr) uintptr {
    rvalue := runSyscall(callid, argh...)
    return uintptr(rvalue)
}

func runSyscall(callid uint16, argh ...uintptr) (errcode uint32)

func LoadFunctionFromHash(
	hashing_algorithm func(string) string,
	hashedName string,
	dll *pe.File,
) (uint16, error) {

	/* retrieve function exports */
	exports, err := dll.Exports()
	if err != nil {
		return 0, err
	}

	for _, x := range exports {

		/* hash every export & compare against base hash */
		if hashing_algorithm(x.Name) == hashedName {

			/* get in-memory offset from rva */
			offset := rva2offset(dll, x.VirtualAddress)
            dllBytes, err := dll.Bytes(); if err != nil {
                return 0, errors.New("could not retrieve bytes from dll...")
            }

            buff := dllBytes[offset : offset + 10]
            sysId := binary.LittleEndian.Uint16(buff[4:8])
			return sysId, nil
		}
	}
	return 0, errors.New("Function not found")
}
