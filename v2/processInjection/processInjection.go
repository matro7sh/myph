package processinjection

import "github.com/cmepw/myph/v2/utils"

// ProcessInjectionConfig stores all the information related to loading a Process Injection method
type ProcessInjectionConfig struct {
	SleepTime int       // sleep-time before triggering the execution
	Target    string    // TargetProcess
	Technique Technique // shellcode-loading technique

	// TODO(djnn): add here ExecFunctionName && sleep-obfuscation method support
	// maybe this object should also keep in memory the Win32 dependencies so that they can be loaded by APIHashingConfig
}

type Technique string

const (
	CRT               Technique = "CRT"
	CRTx              Technique = "CRTx"
	ETWP              Technique = "Etwp"
	SYSCALL           Technique = "Syscall"
	SYSCALLTEST       Technique = "SyscallTest"
	EnumTreeW         Technique = "EnumTreeW"
	NtCreateThreadEx  Technique = "NtCreateThreadEx"
	CreateFiber       Technique = "CreateFiber"
	CreateThread      Technique = "CreateThread"
	ProcessHollowing  Technique = "ProcessHollowing"
	EnumCalendarInfoA Technique = "EnumCalendarInfoA"
)

func (e *Technique) String() string {
	return string(*e)
}

func (e *Technique) Set(v string) error {
	err := utils.ValidateString(
		v,
		[]string{
			"CRT",
			"CRTx",
			"Etwp",
			"Syscall",
			"CreateFiber",
			"NtCreateThreadEx",
			"EnumCalendarInfoA",
			"EnumTreeW",
			"ProcessHollowing",
			"CreateThread",
		},
	)
	if err != nil {
		return err
	}
	*e = Technique(v)
	return nil
}

func (e *Technique) Type() string {
	return "Win32 (CRT, CRTx, CreateFiber, ProcessHollowing, CreateThread, NtCreateThreadEx, Etwp, Syscall, EnumTreeW, EnumCalendarInfoA)"
}
