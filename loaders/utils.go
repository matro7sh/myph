package loaders

func SelectTemplate(templateName string) func(string) string {

	switch templateName {
	case "CRT":
		return GetCRTTemplate

	case "CreateThread":
		return GetCreateThreadTemplate

	case "ProcessHollowing":
		return GetProcessHollowingTemplate

	case "Syscall":
		return GetSyscallTemplate

	case "Callback":
		return GetCallbackTemplate
	}

	return nil
}
