package internals

/*
   slightly adapted from hooka loader

   i could have just yoinked the code and used it like that but i plan to
   do different things in the future, which will need me to implement things
   differently, but this is an excellent base if you want to get started
   or use a more stable loader :)


*/

import (
	"errors"

	"github.com/Binject/debug/pe"
)

func rva2offset(pe *pe.File, rva uint32) uint32 {
	for _, hdr := range pe.Sections {

		virtualAddr := uint64(hdr.VirtualAddress)
		virtualSize := uint64(hdr.VirtualAddress + hdr.VirtualSize)
		base := uint64(rva)

		if base < virtualSize && base > virtualAddr {
			return rva - hdr.VirtualAddress - hdr.Offset
		}
	}

	return rva
}

func LoadFunctionFromHash(
	hashing_algorithm func(string) string,
	hashedName string,
	dll *pe.File,
) (uintptr, error) {

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
			return uintptr(offset), nil
		}
	}
	return 0, errors.New("Function not found")
}
