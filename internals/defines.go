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
	{
		Name:   "VirtualAlloc",
		Sha1:   "3567705df8e544d414d315f64ae47e5861b0f68a",
		Sha256: "02bd37c1a0f05945da5b89a6bac0442c25ed41d4ef7faf5a0dbebc4a164717a4",
		Sha512: "d07e14fb68a140227321c46c4a59cf1a9a821c0f0add4aa0bf9b9a875c3af974857855052e329d8d90491b4d4376e1249d6776f725ca763fe0f53cd84a7ff942",
		Djb2:   "782024e6b5fe6881",
	},
	{
		Name:   "VirtualProtect",
		Sha1:   "69e06440b787b5b3fac43a60d3f019be95f63896",
		Sha256: "9e14bfc8aef4a854ac77a1ae7ae1e0c3b072aec6c2da284164a0b9ea347fdaba",
		Sha512: "77dad9a3279de993b2edff84ceae8c18ec4577f75bc3157694fe1349df9d99300e999d9d25f6619a839022dc96c037877d93bb89d83cb7600cdd544fbf059d14",
		Djb2:   "7126a1d34679917e",
	},
	{
		Name:   "RtlCopyMemory",
		Sha1:   "638f1a50566e7a2aceaeeebc63980672611c32a0",
		Sha256: "8c6f5c89104c0c4418fcda502146888ac9a255697f7aeb62171da677a6bf34b2",
		Sha512: "4a7eab1b5ad1d3d71c105cdc50e47aa944b0c56cb00bb896a5ad652ccca4f9e1a8a84d757f3158aeec5104cb4b2d1f7923e21a5ba8f75180a112fda40722f70c",
		Djb2:   "7a4c2ed807c8fcf1",
	},
}

func LoadLibraryA(lpLibFileName *uint8) uintptr
