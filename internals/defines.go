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
	{
		Name:   "NtProtectVirtualMemory",
		Sha1:   "059637f5757d91ad1bc91215f73ab6037db6fe59",
		Sha256: "a6290493ec0ae72f94b5e4507d63420e40d5e35404d99a583a62acfedddfd848",
		Sha512: "e07953c6b45a10b35f74686e9723e3ce65b3506332231c314ff88cb9b86824c756aa9ec1642a55e7fbf0521d9e68e6b09b4c423327ab780100d92a0961d4c250",
		Djb2:   "a9a7b2ecdd745a31",
	},
	{
		Name:   "NtAllocateVirtualMemory",
		Sha1:   "04262a7943514ab931287729e862ca663d81f515",
		Sha256: "078b183f59677940916dc1da6726b10497d230dff219f845c7d04c1f0425c388",
		Sha512: "15cf362b1abdc2792899e7e451e2c7e0668ff0bf5df6b9a4fa92082b6abd77c8c14ec684c98af255f6cd2af58c72a810332887aa0e18b076dd58da2b1bc1bea0",
		Djb2:   "32b0ac787d4dba31",
	},
	{
		Name:   "NtCreateThreadEx",
		Sha1:   "91958a615f982790029f18c9cdb6d7f7e02d396f",
		Sha256: "a3b64f7ca1ef6588607eac4add97fd5dfbb9639175d4012038fc50984c035bcd",
		Sha512: "ef9ef2ae72efe49a5eff53df67fc402e49d2324eef4bc6dbb6f3797d9a1f00f82089620103a29aef6be741c0e19d469855cad7cc023a05685b2399ee10065fa0",
		Djb2:   "76d3925c21b6534a",
	},
	{
		Name:   "NtWriteVirtualMemory",
		Sha1:   "6caed95840c323932b680d07df0a1bce28a89d1c",
		Sha256: "6d51355d37c96dec276ee56a078256831610ef9b42287e19e1b85226d451410b",
		Sha512: "f07fcea516c70bda3cb17f3010d2d03ea426a79e4ca181668728ce02a93c39673d8e38de51f68574034f3dfa87eb5f98d3e279015673194b5bee86fa2eb8ac12",
		Djb2:   "9ca2ab4726e0ba31",
	},
}
