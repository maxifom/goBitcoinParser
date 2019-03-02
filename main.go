package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sort"
	"time"
)

type Header struct {
	Version           uint32
	PreviousBlockHash []byte
	MerkleRoot        []byte
	Timestamp         uint32
	Bits              uint32
	Nonce             uint32
}

type Input struct {
	PreviousTransactionHash     []byte
	PreviousTransactionOutIndex uint32
	ScriptLength                uint64
	Script                      []byte
	DecodedScript               string
	SequenceNo                  []byte
}

type Output struct {
	Value        uint64
	ScriptLength uint64
	Script       []byte
}

type Transaction struct {
	Hash          []byte
	Version       uint32
	InputCounter  uint64
	Inputs        []Input
	OutputCounter uint64
	Outputs       []Output
	LockTime      uint32
}

type Block struct {
	Hash               []byte
	Size               uint32
	Header             Header
	TransactionCounter uint64
	Transactions       []Transaction
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB\n", bToMb(m.Sys))
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func main() {
	logFile, _ := os.OpenFile("blocks.txt", os.O_RDWR|os.O_CREATE, 0666)
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(0)
	now := time.Now()
	blocks, e := ioutil.ReadFile("blk00000.dat")
	if e != nil {
		log.Println(e)
	}
	size := int64(binary.Size(blocks))
	fmt.Println(size)
	duration := time.Now().UnixNano() - now.UnixNano()
	fmt.Println(duration)
	fmt.Println(float64(duration) / 1e9)
	speed := float64(size) / float64(duration)
	fmt.Println(speed, "bytes/ns")
	fmt.Println(speed*1e9/1024/1024, "MB/s")
	magicBytes := blocks[0:4]
	split := bytes.Split(blocks, magicBytes)
	//blocksToSave := make([]Block, len(split)-1)
	var blocksToSave []Block
	for _, block := range split[1:] {
		var b Block
		blockHash := doubleSHA256(block[4:84])
		b.Hash = SwapOrder(blockHash[:])
		size := block[0:4]
		b.Size = u32(size)
		version := block[4:8]
		b.Header.Version = u32(version)
		b.Header.PreviousBlockHash = SwapOrder(block[8:40])
		b.Header.MerkleRoot = SwapOrder(block[40:72])
		timestamp := u32(block[72:76])
		b.Header.Timestamp = timestamp
		bits := block[76:80]
		b.Header.Bits = u32(bits)
		nonce := block[80:84]
		b.Header.Nonce = u32(nonce)
		txCount, n := DecodeVarint(block[84:93])
		b.TransactionCounter = txCount
		var nextByte uint64
		//b.Transactions = make([]Transaction, txCount)
		nextByte = uint64(84 + n)
		var q uint64
		for q = 0; q < txCount; q++ {
			var tx Transaction
			txStart := nextByte
			tx.Version = u32(block[nextByte : nextByte+4])
			nextByte += 4
			inputCounter, n := DecodeVarint(block[nextByte : nextByte+9])
			tx.InputCounter = inputCounter
			//tx.Inputs = make([]Input, tx.InputCounter)
			nextByte += uint64(n)
			var _input uint64
			for _input = 0; _input < inputCounter; _input++ {
				var input Input
				input.PreviousTransactionHash = block[nextByte : nextByte+32]
				nextByte += 32
				input.PreviousTransactionOutIndex = u32(block[nextByte : nextByte+4])
				nextByte += 4
				inputScriptLength, n := DecodeVarint(block[nextByte : nextByte+9])
				input.ScriptLength = inputScriptLength
				nextByte += uint64(n)
				input.Script = block[nextByte : nextByte+inputScriptLength]
				nextByte += inputScriptLength
				input.SequenceNo = block[nextByte : nextByte+4]
				nextByte += 4
				tx.Inputs = append(tx.Inputs, input)
			}
			outputCounter, n := DecodeVarint(block[nextByte : nextByte+9])
			tx.OutputCounter = outputCounter
			//tx.Outputs = make([]Output, tx.OutputCounter)
			nextByte += uint64(n)
			var _output uint64
			for _output = 0; _output < outputCounter; _output++ {
				var output Output
				output.Value = u64(block[nextByte : nextByte+8])
				nextByte += 8
				outputScriptLength, n := DecodeVarint(block[nextByte : nextByte+9])
				output.ScriptLength = outputScriptLength
				nextByte += uint64(n)
				output.Script = block[nextByte : nextByte+outputScriptLength]
				nextByte += outputScriptLength
				tx.Outputs = append(tx.Outputs, output)
			}
			tx.LockTime = u32(block[nextByte : nextByte+4])
			nextByte += 4
			txHash := doubleSHA256(block[txStart:nextByte])
			tx.Hash = SwapOrder(txHash[:])
			b.Transactions = append(b.Transactions, tx)
		}
		blocksToSave = append(blocksToSave, b)
	}

	sort.Slice(blocksToSave, func(i, j int) bool {
		if blocksToSave[i].Header.Timestamp == blocksToSave[j].Header.Timestamp {
			if bytes.EqualFold(blocksToSave[i].Header.PreviousBlockHash, blocksToSave[j].Hash) {
				return false
			} else if bytes.EqualFold(blocksToSave[j].Header.PreviousBlockHash, blocksToSave[i].Hash) {
				return true
			} else {
				fmt.Println("Time equal and no prev block hash found")
				fmt.Printf("%x != %x \n", blocksToSave[j].Header.PreviousBlockHash, blocksToSave[i].Hash)
				fmt.Printf("%x != %x \n", blocksToSave[i].Header.PreviousBlockHash, blocksToSave[j].Hash)
				fmt.Printf("Time: %d,%d\n", blocksToSave[i].Header.Timestamp, blocksToSave[j].Header.Timestamp)
			}
		}
		return blocksToSave[i].Header.Timestamp < blocksToSave[j].Header.Timestamp
	})

	for _, b := range blocksToSave {
		b.Print()
	}
	PrintMemUsage()
}

func doubleSHA256(b []byte) [32]byte {
	firstHash := sha256.Sum256(b)
	return sha256.Sum256(firstHash[:])
}

func u32(buf []byte) uint32 {
	return binary.LittleEndian.Uint32(buf)
}
func u64(buf []byte) uint64 {
	return binary.LittleEndian.Uint64(buf)
}

func u16(buf []byte) uint16 {
	return binary.LittleEndian.Uint16(buf)
}
func DecodeVarint(buf []byte) (x uint64, n int) {
	b := []byte{0}
	reader := bytes.NewReader(buf)
	_, err := reader.Read(b)
	if err != nil {
		return
	}
	switch b[0] {
	case 0xfd:
		var s uint16
		err = binary.Read(reader, binary.LittleEndian, &s)
		if err != nil {
			return
		}
		return uint64(s), 3
	case 0xfe:
		var w uint32
		err = binary.Read(reader, binary.LittleEndian, &w)
		if err != nil {
			return
		}
		return uint64(w), 5
	case 0xff:
		var dw uint64
		err = binary.Read(reader, binary.LittleEndian, &dw)
		if err != nil {
			return
		}
		return uint64(dw), 9
	default:
		return uint64(b[0]), 1
	}
}

func SwapOrder(arr []byte) []byte {
	var temp byte
	length := len(arr)
	for i := 0; i < length/2; i++ {
		temp = arr[i]
		arr[i] = arr[length-i-1]
		arr[length-i-1] = temp
	}
	return arr
}

func (block *Block) Print() {
	log.Printf("Block %x\n", block.Hash)
	log.Printf("Size %d\n", block.Size)
	log.Printf("Version %d\n", block.Header.Version)
	log.Printf("Previous Block Hash %x\n", block.Header.PreviousBlockHash)
	log.Printf("Merkle Root %x\n", block.Header.MerkleRoot)
	log.Printf("Timestamp %d\n", block.Header.Timestamp)
	log.Printf("Bits %d\n", block.Header.Bits)
	log.Printf("Nonce %d\n", block.Header.Nonce)
	log.Printf("Transaction Count %d\n", block.TransactionCounter)
	for _, t := range block.Transactions {
		log.Printf("Hash %x\n", t.Hash)
		log.Printf("Version %d\n", t.Version)
		log.Printf("Input Counter %d\n", t.InputCounter)
		for _, i := range t.Inputs {
			log.Printf("Prev Tx Hash %x\n", i.PreviousTransactionHash)
			log.Printf("Prev Tx Out index %d\n", i.PreviousTransactionOutIndex)
			log.Printf("Script length %d\n", i.ScriptLength)
			log.Printf("Script %x\n", i.Script)
			log.Printf("Sequence no %x\n", i.SequenceNo)
		}
		log.Printf("Output Counter %d\n", t.OutputCounter)
		for _, o := range t.Outputs {
			log.Printf("Value %d\n", o.Value)
			log.Printf("Script Length %d\n", o.ScriptLength)
			log.Printf("Script %x\n", o.Script)

		}
		log.Printf("Lock time %d\n", t.LockTime)
	}

}
