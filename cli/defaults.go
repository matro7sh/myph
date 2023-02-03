package cli

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
    opts := Options{
        ShellcodePath: "",
        Outfile: "slipak",
    }

    return opts
}
