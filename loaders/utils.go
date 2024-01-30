package loaders

func InformExpermimental() {
	println("[!] The API hashing feature is still in an an experimental stage!!")
	println("Only a few methods are supported for now:")
	println("\t-Syscall\n\t-CreateThread\n\t-NtCreateThreadEx\n")
}

func InformProcessUnused(process string) {
	_ = process

	println("[!] PLEASE NOTE:\n\tshellcode will not be injected into new process with this method.")
}

func DownloadMyphInternals(path string) error {

	println("[!] While internals module is not published, we will manually copy it.")
	println("Please ensure (temporarily) that you use myph from its root repository.")

	return nil
}

type Templater interface {
	Init() string
	Import() string
	Const() string
	Process() string
	GetTemplate(targetProcess string) string
}

func SelectTemplate(templateName string, useApiHashing bool, apiHashTechnique string) func(string) string {

	// TODO(djnn): finish transitionning methods here
	var methodes = map[string]Templater{
		"Syscall":           SysTemplate{UseApiHashing: useApiHashing, HashMethod: apiHashTechnique},
		"CRT":               CRTTemplate{},
		"CRTx":              CRTxTemplate{},
		"CreateThread":      CreateTTemplate{UseApiHashing: useApiHashing, HashMethod: apiHashTechnique},
		"ProcessHollowing":  ProcHollowTemplate{},
		"EnumCalendarInfoA": EnumCalendarTemplate{},
		"CreateFiber":       CreateFiberTemplate{},
		"Etwp":              ETWPTemplate{},
		"NtCreateThreadEx":  NtCreateThreadExTemplate{UseApiHashing: useApiHashing, HashMethod: apiHashTechnique},
	}

	if useApiHashing {
		InformExpermimental()
	}

	template, exist := methodes[templateName]
	if exist {
		return template.GetTemplate
	}
	return nil
}
