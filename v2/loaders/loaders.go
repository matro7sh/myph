package loaders

func InformAPIHashingExperimental() {
	println("[!] The API hashing feature is still in an an experimental stage!!")
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
