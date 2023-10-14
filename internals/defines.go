package internals

/* stores hashed name for different functions here. */

type ItemHash struct {
	Name   string
	Djb2   string
	Sha1   string
	Sha256 string
	Sha512 string
}

var Libraries = []ItemHash{
	{
		Name:   "ntdll.dll",
		Sha1:   "0ebd8d889e0e2c63b7a4361a8dfe00177cdd90bb",
		Sha256: "9799dda2257cafa991aa38a16bca3fef8e1dc74a710a45540f92b1fa6bebb325",
		Sha512: "40b2a7d054581eb002a782e52bdfa0fe3a3785bacb3f68417a8398ca36767789161444cf3730f9add8e336f238302677f1695fa85d86e2f38f774c22133a2c73",
		Djb2:   "48974c2b9a61004",
	},
}

var Ntdll = []ItemHash{
	{
		Name:   "LoadLibraryA",
		Sha1:   "2ff89c407367034615a95207770da1a7646d47df",
		Sha256: "ebe7efccb0a610c6a5c504c1c40e39b9c17ffcf22165a0cfc352ec24ae254bbf",
		Sha512: "0769713cb7eeadc2cca33e363131b0ab52b1df0d9b1ad834dd6e4e5b8aa04e384d058039328cd11f8e526ba8f2aaf326f679d100f607ce118443cce079dcb82f",
		Djb2:   "6e8ac3a04c15d943",
	},
}
