package loaders

func InformExpermimental() {
	println("\tThis feature is still in an an experimental stage.")
}

func InformProcessUnused(process string) {
	_ = process

	println("\n\n[!] PLEASE NOTE:\n\tshellcode will not be injected into new process with this method")
}

type Templater interface {
	Init() string
	Import() string
	Const() string
	Process() string
	GetTemplate(targetProcess string) string
}

var methodes = map[string]Templater{
	"Syscall":           SysTemplate{},
	"CRT":               CRTTemplate{},
	"CRTx":              CRTxTemplate{},
	"CreateThread":      CreateTTemplate{},
	"ProcessHollowing":  ProcHollowTemplate{},
	"EnumCalendarInfoA": EnumCalendarTemplate{},
	"CreateFiber":       CreateFiberTemplate{},
	"Etwp":              ETWPTemplate{},
}

func SelectTemplate(templateName string) func(string) string {

	template, exist := methodes[templateName]
	if exist {
		return template.GetTemplate
	}
	return nil
}
