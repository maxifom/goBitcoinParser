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
	"time"
)

type Header struct {
	Version           uint32
	PreviousBlockHash [32]byte
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
	Hash               [32]byte
	Size               uint32
	Header             Header
	TransactionCounter uint64
	Transactions       []Transaction
	Next               *Block
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB\n", bToMb(m.Alloc))
	fmt.Printf("TotalAlloc = %v MiB\n", bToMb(m.TotalAlloc))
	fmt.Printf("Sys = %v MiB\n", bToMb(m.Sys))
	fmt.Printf("Frees = %v\n", m.Frees)
	fmt.Printf("Mallocs = %v\n", m.Mallocs)
	fmt.Printf("HeapAlloc = %vMiB\n", bToMb(m.HeapAlloc))
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func main() {
	programStart := time.Now()
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
	blocksToSave := make([]Block, len(split)-1)
	var nextByte uint64
	var q uint64
	var _input uint64
	var _output uint64
	var n uint64
	prevBlockMap := map[[32]byte]int{}
	var reader *bytes.Reader
	var buf32 [32]byte
	for _i, block := range split[1:] {
		reader = bytes.NewReader(block)
		blocksToSave[_i].Hash = SwapOrder32(doubleSHA256(block[4:84]))
		blocksToSave[_i].Size = u32(block[0:4])
		blocksToSave[_i].Header.Version = u32(block[4:8])
		_, _ = reader.ReadAt(buf32[:], 8)
		blocksToSave[_i].Header.PreviousBlockHash = SwapOrder32(buf32)
		prevBlockMap[blocksToSave[_i].Header.PreviousBlockHash] = _i
		blocksToSave[_i].Header.MerkleRoot = SwapOrder(block[40:72])
		blocksToSave[_i].Header.Timestamp = u32(block[72:76])
		blocksToSave[_i].Header.Bits = u32(SwapOrder(block[76:80]))
		blocksToSave[_i].Header.Nonce = u32(block[80:84])
		blocksToSave[_i].TransactionCounter, n = DecodeVarint(block[84:93])
		nextByte = 84 + n
		blocksToSave[_i].Transactions = make([]Transaction, blocksToSave[_i].TransactionCounter)
		for q = 0; q < blocksToSave[_i].TransactionCounter; q++ {
			txStart := nextByte
			blocksToSave[_i].Transactions[q].Version = u32(block[nextByte : nextByte+4])
			nextByte += 4
			blocksToSave[_i].Transactions[q].InputCounter, n = DecodeVarint(block[nextByte : nextByte+9])
			nextByte += n
			blocksToSave[_i].Transactions[q].Inputs = make([]Input, blocksToSave[_i].Transactions[q].InputCounter)
			for _input = 0; _input < blocksToSave[_i].Transactions[q].InputCounter; _input++ {
				blocksToSave[_i].Transactions[q].Inputs[_input].PreviousTransactionHash = block[nextByte : nextByte+32]
				nextByte += 32
				blocksToSave[_i].Transactions[q].Inputs[_input].PreviousTransactionOutIndex = u32(block[nextByte : nextByte+4])
				nextByte += 4
				blocksToSave[_i].Transactions[q].Inputs[_input].ScriptLength, n = DecodeVarint(block[nextByte : nextByte+9])
				nextByte += n
				blocksToSave[_i].Transactions[q].Inputs[_input].Script = block[nextByte : nextByte+blocksToSave[_i].Transactions[q].Inputs[_input].ScriptLength]
				nextByte += blocksToSave[_i].Transactions[q].Inputs[_input].ScriptLength
				blocksToSave[_i].Transactions[q].Inputs[_input].SequenceNo = block[nextByte : nextByte+4]
				nextByte += 4
			}
			blocksToSave[_i].Transactions[q].OutputCounter, n = DecodeVarint(block[nextByte : nextByte+9])
			nextByte += uint64(n)
			blocksToSave[_i].Transactions[q].Outputs = make([]Output, blocksToSave[_i].Transactions[q].OutputCounter)
			for _output = 0; _output < blocksToSave[_i].Transactions[q].OutputCounter; _output++ {
				blocksToSave[_i].Transactions[q].Outputs[_output].Value = u64(block[nextByte : nextByte+8])
				nextByte += 8
				blocksToSave[_i].Transactions[q].Outputs[_output].ScriptLength, n = DecodeVarint(block[nextByte : nextByte+9])
				nextByte += n
				blocksToSave[_i].Transactions[q].Outputs[_output].Script = block[nextByte : nextByte+blocksToSave[_i].Transactions[q].Outputs[_output].ScriptLength]
				nextByte += blocksToSave[_i].Transactions[q].Outputs[_output].ScriptLength
			}
			blocksToSave[_i].Transactions[q].LockTime = u32(block[nextByte : nextByte+4])
			nextByte += 4
			txHash := doubleSHA256(block[txStart:nextByte])
			blocksToSave[_i].Transactions[q].Hash = SwapOrder(txHash[:])
		}
	}
	PrintMemUsage()
	fmt.Printf("Program took %f s\n", time.Since(programStart).Seconds())
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

func DecodeVarint(buf []byte) (x uint64, n uint64) {
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
		return dw, 9
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

func SwapOrder32(arr [32]byte) [32]byte {
	var temp byte
	for i := 0; i < 16; i++ {
		temp = arr[i]
		arr[i] = arr[31-i]
		arr[31-i] = temp
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
