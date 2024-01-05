package loaders

func InformExpermimental() {
	println("\tThis feature is still in an an experimental stage.")
}

func InformProcessUnused(process string) {
	_ = process

	println("\n\n[!] PLEASE NOTE:\n\tshellcode will not be injected into new process with this method")
}

func SelectTemplate(templateName string) func(string) string {

	switch templateName {
	case "CRT":
		return GetCRTTemplate

	case "CRTx":
		return GetCRTxTemplate

	case "CreateThread":
		return GetCreateThreadTemplate

	case "NtCreateThreadEx":
		return GetNtCreateThreadExTemplate

	case "ProcessHollowing":
		return GetProcessHollowingTemplate

	case "Syscall":
		return GetSyscallTemplate

	case "SyscallTest":
		return GetSyscallAPIHashTemplate

	case "CreateFiber":
		return GetCreateFiberTemplate

	case "Etwp":
		return GetEtwpCreateEtwThreadTemplate

	}

	return nil
}
