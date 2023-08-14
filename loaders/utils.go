package loaders

func InformProcessUnused(process string) {
	_ = process

	println("\n\n[!] PLEASE NOTE: shellcode will not be injected into new process with this method")
}

func SelectTemplate(templateName string) func(string) string {

	switch templateName {
	case "CRT":
		return GetCRTTemplate

	case "CRTx":
		return GetCRTxTemplate

	case "CreateThread":
		return GetCreateThreadTemplate

	case "ProcessHollowing":
		return GetProcessHollowingTemplate

	case "Syscall":
		return GetSyscallTemplate

	case "CreateFiber":
		return GetCreateFiberTemplate

	}

	return nil
}
