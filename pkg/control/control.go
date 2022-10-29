package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MTU should never be set below 576. This will prevent control packet fragmentation.
// IP header=20
// UDP header=8
// GVCP header=8
// Max GVCP payload=540
// Total=576
const GVCP_PORT = 3956
const STREAM_PORT = 55555
const MAX_MTU = 9000

type Register struct {
	Address string
	Value   string
}

type RegisterBank struct {
	Auth                Register
	GevHeartbeatTimeout Register
	STREAM_DESTINATION  Register
	STREAM_DESTINATION2 Register
	GevSCPHostPort      Register
	GevSCPSPacketSize   Register
	AcquisitionMode     Register
	PixelFormat         Register
	Width               Register
	Height              Register
	OffsetX             Register
	OffsetY             Register
	REG12_PACKET_SIZE   Register
	GainAuto            Register
	AcquisitionStart    Register
	AcquisitionStop     Register

	FREE_RUN                  Register
	IDK_STREAM_DESTINATION    Register
	GevIEEE1588               Register
	GevIEEE1588DataSetLatch   Register
	SyncFreeRunTimerUpdate    Register
	TEST                      Register
	DeviceModelName           Register
	AcquisitionFrameRateAbs   Register
	PreAcquisitionStart       Register
	IDK2                      Register
	GevSCPD                   Register
	DeviceLinkThroughputLimit Register
}
type Camera struct {
	ModelName    string
	CameraName   string
	OutputFormat int     //0 no-debayer, 1 debayer
	PixelFormat  int     // 01=Mono8 0b=BayerRG8 14=BayerRG12 (int 20) 15=BayerRG12Packed
	BitDepth     int     //8 for 8bit images
	Gamma        float64 //1 for no gamma adjustment
	//SaveCommand string //either 82 (register) or 86 (memory)
	CameraIp string //camera IP
	//CameraStreamPort       uint32
	CameraStreamSourcePort uint32
	CameraIpLong           uint32 //camera IP
	HostIp                 string //host computer IP
	MTU                    int
	HostPort               int
	//AuthCommand            string
	SaveCommand string //82 (default fo basler) or 86
	Width       int    //?
	Height      int    //?
	Path        string //path to write files for saved camera frames

	//GevSCPSPacketSize string //?
	Verbose bool
	RegisterBank
}
type CameraPing struct {
	//IP          net.Addr
	CameraIp          string
	Id                string
	Name              string
	ModelName         string
	Firmware          string
	Width             string
	Height            string
	GevSCPSPacketSize string
	PacketResponse    []byte
}

func NewCamera(hostIp string, cameraIp string, cameraStreamPort uint32, modelName string) Camera {
	//here are the addresses for registers you may want to change (FYI- you always need to set the stream dest)
	rBank := RegisterBank{
		Auth:                Register{"00000a00", "00000002"}, //_ WILLRESET 00000000 or 2 *
		GevHeartbeatTimeout: Register{"00000938", "00002328"}, //bb8 3000ms
		STREAM_DESTINATION:  Register{"00000D18", "00000000"}, //WILLRESET00000000 echo "obase=16;169"|bc WILLRESET		STREAM_DESTINATION2:     Register{"00000B18", "00000000"}, //a9fe60c7
		STREAM_DESTINATION2: Register{"00000B18", "00000000"}, //00000000 echo "obase=16;169"|bc WILLRESET		STREAM_DESTINATION2:     Register{"00000B18", "00000000"}, //a9fe60c7
		GevSCPHostPort:      Register{"00000D00", "0000d903"}, //WILLRESET00000000  d903=55555 WILLRESET
		//regular settings
		GevSCPSPacketSize: Register{"00000D04", "00002328"}, //default 0x2328=9000, 0x05dc=1500
		AcquisitionMode:   Register{"00040004", "00000000"}, //_ 01 is not valid, 00 is SingleFrame and 02 is continuous
		PixelFormat:       Register{"00030024", "00000001"}, //_ 01=Mono8 0b=BayerRG8=(11 int) 14=BayerRG12(20 int)15=BayerRG12Packed 2b=YUV422Packed 2c=YUV422_YUYV_Packed
		Width:             Register{"00030204", "000003e8"}, //x0990=2448 x0064=100 1f4=500 3e8=1000
		Height:            Register{"00030224", "000003e8"}, //x0800=2048 for level 10
		OffsetX:           Register{"00030244", "00000004"},
		OffsetY:           Register{"00030264", "00000002"}, //500 for level 10 //was 1f4
		REG12_PACKET_SIZE: Register{"40000500", "00000000"},
		GainAuto:          Register{"00020004", "00000001"}, //was 1
		AcquisitionStart:  Register{"00040024", "00000000"}, //set to 1
		TEST:              Register{"1040001c", "00000b18"},
		//MEM:                     Register{"10300004", "00000001"},
		PreAcquisitionStart:     Register{"10300008", "0000001"},
		DeviceModelName:         Register{"00000000", "00000000"}, //READ ONLY
		AcquisitionFrameRateAbs: Register{"000404a4", "00030d40"}, //in microseconds 5Hz=00003d40=200,000 6Hz=028B0A=166,666
		IDK2:                    Register{"11400000", "00000000"},
		/* End the 15 registers that you get from gige -write "42 01 00 02 00 00 ff ff" */
		GevSCPD:                   Register{"00000D00", "000055f0"}, //interpacket delay 22000 min:0 max:76997
		DeviceLinkThroughputLimit: Register{"101001f4", "02faf080"}, //50MB/s untested
		//		AcquisitionStop:          Register{"00040044", "00000000"},
		//		FREE_RUN:                Register{"00210004", "00000001"},
		//		IDK_STREAM_DESTINATION:  Register{"00000b10", "00000000"},
		//		GevIEEE1588:             Register{"00000954", "00080000"},
		//		GevIEEE1588DataSetLatch: Register{"00010184", "00000000"},
		//		SyncFreeRunTimerUpdate:  Register{"00210304", "00000000"},
	}
	rBank.STREAM_DESTINATION.Value = Ip2Hex(hostIp)
	rBank.STREAM_DESTINATION2.Value = Ip2Hex(hostIp)
	rBank.IDK_STREAM_DESTINATION.Value = Ip2Hex(hostIp)
	//	saveCommand := "82" //default to save in registers
	//authCommand := "420100820010000100000a0000000002" //write Auth to register by default
	saveCommand := "82"
	println("modelName=", modelName)
	if modelName == "TRI081S-C" {
		rBank.AcquisitionStart.Address = "10300004"
		rBank.Width.Address = "10400000"
		rBank.Height.Address = "10400014"
		rBank.PixelFormat.Address = "10400060"             //mono8=01080001 BayerRG8=01080009
		rBank.AcquisitionFrameRateAbs.Address = "10300014" //really AcquisitionFrameRate
		//authCommand = "420100820008000100000a0000000002"   //Lucid cameras neet to write the Auth to Memory, not Register
		saveCommand = "86" //save in memory instead
		//		saveCommand = "82" //save in memory instead
		//println("model=", modelName)
		//Lucid Vision Labs-TRI081S-C-212000517 (192.168.1.101)
		//AcquisitionFrameRate = 20.2614 Hz min:0.1 max:20.2614
		//arv-tool-0.8 control DeviceLinkThroughputLimit
		//Lucid Vision Labs-TRI081S-C-212000517 (192.168.1.101)
		//DeviceLinkThroughputLimit = 125000000 Bps min:31250000 max:125000000
	} else if modelName == "Nano-C1920" {
		rBank.Width.Address = "20000070"  //values are byteswapped, 20030000 = 00000320
		rBank.Height.Address = "20000090" //ditto
	} else if modelName == "a2A5320-7gc" {
		saveCommand = "86"
		rBank.AcquisitionMode.Address = "10001068"
		rBank.AcquisitionStart.Address = "1000859c"
		rBank.Width.Address = "10003948"
		//rBank.MaxHeight.Address = "10003950"
		rBank.Height.Address = "10003958"
		rBank.GevSCPSPacketSize.Address = "10001334"
		//rBank.PreAcquisitionStart.Address = "100085a0"

		//	0x0010:  a9fe 1e8d d459 0f74 0018 8aca 4201 0086
		//	0x0020:  0008 0314 1000 1068 0000 0000
		//--
		//	0x0010:  a9fe 1e8d d459 0f74 0018 8aca 4201 0086
		//	0x0020:  0008 0315 1000 859c 0000 0001

		//} else if modelName == "a2A5320-7gcPRO" {
		//	rBank.Auth.Address = "10001068"
		//	rBank.AcquisitionStart.Address = "1000859c"
	}
	camera := Camera{
		ModelName:   modelName,
		SaveCommand: saveCommand,
		HostIp:      hostIp,
		CameraIp:    cameraIp,
		//CameraStreamPort: cameraStreamPort,
		HostPort:     STREAM_PORT,
		CameraIpLong: IpStr2Long(cameraIp),
		RegisterBank: rBank,
		//AuthCommand:  authCommand, //whether to write auth to memory or register (default)
	}
	return camera
}
func IpStr2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}

// converts a comman name register address for a particular camera to its hex string, using the register bank struct as a lookup
// GetAddress("Width") ->   "00030204"
func (regBank RegisterBank) GetAddress(name string) (address string) {
	name = strings.ReplaceAll(name, " ", "")
	if len(name) > 10 && name[0] == 'R' && name[1] == '[' {
		if name[2] == '0' && name[3] == 'x' {
			return name[4:12] //R[00030204] format
		} else {
			return name[2:10] //R[0x00030204] format
		}
	}
	s := reflect.ValueOf(regBank)
	typeOfT := s.Type()
	if typeOfT.Kind() == reflect.Ptr {
		typeOfT = typeOfT.Elem()
	}
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		if typeOfT.Field(i).Name == name {
			return f.FieldByName("Address").String()
		}
	}
	return
}
func (regBank RegisterBank) GetName(address string) (name string) {
	s := reflect.ValueOf(regBank)
	typeOfT := s.Type()
	if typeOfT.Kind() == reflect.Ptr {
		typeOfT = typeOfT.Elem()
	}
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		if f.FieldByName("Address").String() == address {
			return typeOfT.Field(i).Name
		}
	}
	return
}

// this takes the string input and if less that 8 char, assumes integer input or ip address and converts to hex
func ValueToHex(value string) (hexValue string, err error) {
	if len(value) < 8 {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%08x", intVal), nil
	}
	arr := strings.Split(value, ".")
	if len(arr) == 4 {
		return Ip2Hex(value), nil
	}
	return value, nil
}

func int2hex(intValue int) (hexValue string) {
	return fmt.Sprintf("%08x", intValue)
}

// this generates the string to write all the register values
// func (regMap RegMap) GetWriteString() (message *string) {
func (camera Camera) GetWriteString() (message *string) {
	regBank := camera.RegisterBank
	body := ""
	v := reflect.ValueOf(regBank)
	typeOfS := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fmt.Printf("Field: %s\tValue: %v\n", typeOfS.Field(i).Name, v.Field(i).Interface())
		reg := v.Field(i).Interface().(Register)
		regId := reg.Address
		regValue := reg.Value
		body = body + regId + regValue
	}

	size := fmt.Sprintf("%04x", len(body)/2) //does not include the 8 byte header in the size
	msgId := "0002"
	header := "42010082" + size + msgId //writeRegister=82  ex: 42010082 00080001
	m := header + body
	return &m
}

func ReadMessage(body string) (message string) {
	size := fmt.Sprintf("%04x", len(body)/2)
	header := "42010080 " + size + " 0001 " //readRegister=80
	m := header + body
	return m
}

//This generates the string to pull values from the registers
//func (regMap RegMap) GetReadString() (message *string) {

func (camera Camera) GetReadString() (message *string) {
	regBank := camera.RegisterBank
	body := ""
	v := reflect.ValueOf(regBank)
	typeOfS := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fmt.Printf("Field: %s\tValue: %v\n", typeOfS.Field(i).Name, v.Field(i).Interface())
		reg := v.Field(i).Interface().(Register)
		regId := reg.Address
		body = body + regId //readOnly
	}
	size := fmt.Sprintf("%04x", len(body)/2)
	header := "42010080 " + size + " 0001" //readRegister=80
	m := header + body
	return &m
}

// send and recieve max 1 packet
type Reply struct {
	IP   net.Addr
	Data []byte
}

func SendReadOnlyUDP(hexMessage, raddr string, conn *net.UDPConn) ([]Reply, error) {
	raddrPtr := net.UDPAddr{IP: net.ParseIP(raddr), Port: GVCP_PORT} //GVCP_PORT
	data, err := hex.DecodeString(hexMessage)
	if err != nil {
		panic(err)
	}
	_, err = conn.WriteToUDP(data, &raddrPtr) //write
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, MAX_MTU) //like 9000 because that is the max packet size
	arr := []Reply{}
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		nRead, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}
		bufferCopy := make([]byte, nRead)
		copy(bufferCopy, buffer[:nRead])
		reply := Reply{
			Data: bufferCopy,
			IP:   addr,
		}
		arr = append(arr, reply)
	}
	return arr, err
}
func (camera Camera) BroadcastHeartbeat(conn *net.UDPConn, delay time.Duration) {
	hexMessage := "420100800004000100000a00" //get AUTH info, hoping this is a universal command across all cameras
	//warning- we are sending the same sequence number "0001" every time
	//for register reads (this might be relying on undefined behavior)

	ticker := time.NewTicker(delay)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case now := <-ticker.C:
			fmt.Printf("\nHeartbeat %s", now.UTC().Format("20060102-150405.000000000"))
			replies, err := SendReadOnlyUDP(hexMessage, "255.255.255.255", conn)
			if err == nil {
				fmt.Printf(" replies")
				for i := 0; i < len(replies); i++ {
					arr := strings.Split(replies[i].IP.String(), ":")
					ip := arr[0]
					fmt.Printf("%v %d=%s data=%x", time.Now(), i, ip, replies[i].Data)
				}

			} else {
				fmt.Printf("err=%v\n", err)
			}
		case <-quit:
			fmt.Println("Received C-c - shutting down")
			sendAddress := "255.255.255.255"
			registerValue := "Auth=0"
			err := camera.SendRegisterValues(conn, sendAddress, registerValue)
			if err != nil {
				println("error sending register values on quit", err)
			}
			/*
				releaseControl := "420100800004000100000a00"
				replies, err := SendReadOnlyUDP(releaseControl, "255.255.255.255", conn)
				if err == nil {
					fmt.Printf(" replies")
					for i := 0; i < len(replies); i++ {
						arr := strings.Split(replies[i].IP.String(), ":")
						ip := arr[0]
						fmt.Printf(" %d=%s", i, ip)
					}
				} else {
					fmt.Printf("err=%v\n", err)
				}
			*/
			time.Sleep(time.Second * 6) //allow 3 + 3 seconds to finish writing udp packets to png output
			os.Exit(0)
			return
		}
	}
}

func GetCameras(ip net.Addr, conn *net.UDPConn) (cameraPings []CameraPing, err error) {
	hexMessage := "420100020000ffff" //get camera info

	replies, err := SendReadOnlyUDP(hexMessage, ip.String(), conn)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(replies); i++ {
		c := CameraPing{}
		modelName := replies[i].Data[112:123]
		j := len(modelName) - 1
		for ; j >= 0 && modelName[j] == 0; j-- {
		}
		modelName = modelName[:j+1] //trim the null characters from the end
		c.ModelName = strings.Trim(string(modelName), "\x00")
		c.Firmware = strings.Trim(string(replies[i].Data[144:160]), "\x00")
		c.Id = strings.Trim(string(replies[i].Data[224:232]), "\x00")
		c.Name = strings.Trim(string(replies[i].Data[232:]), "\x00")
		arr := strings.Split(replies[i].IP.String(), ":")
		ip := arr[0]
		c.CameraIp = ip
		c.PacketResponse = replies[i].Data
		cameraPings = append(cameraPings, c)
	}
	return cameraPings, err
}

// takes a list of register values in common human readable text and returns the values for this camera in hex
// need to depreciate this soon- newer gige cameras do not seem to support fetching multiple registers in a single packet read request (80 or 84)
func (camera Camera) GetCameraRegisters(registerList []string, conn *net.UDPConn) (replyHexArr []string, err error) {
	var body string
	for _, reg := range registerList {
		body = body + camera.GetAddress(reg)
	}
	ip := camera.CameraIp
	messageId := "01"
	command := "84" //80 for 5MP cameras 84 for 16MP doug
	hexMessage := camera.WriteMessage(messageId, command, body)
	replArr, err := SendReadOnlyUDP(hexMessage, ip, conn)

	if err != nil {
		return nil, err
	}
	repl := replArr[0] //should only get one reply packet back
	index := 8         //skip header
	replyHexArr = make([]string, len(registerList))
	for i := range registerList {
		if len(repl.Data) >= index+4 {
			replyHexArr[i] = fmt.Sprintf("%x", repl.Data[index:index+4]) //will be read back in the same order as registerlist
		} else {
			replyHexArr[i] = "0000"
		}
		index += 4 //4 bytes per value
	}
	return replyHexArr, err
}

// takes a single register value in common human readable text and returns the output value for this camera in hex
func (camera Camera) GetCameraRegister(reg string, conn *net.UDPConn) (replyHex string, err error) {
	var body string
	body = body + camera.GetAddress(reg)
	ip := camera.CameraIp
	messageId := "01"
	command := "84" //80 for 5MP cameras 84 for 16MP doug
	hexMessage := camera.WriteMessage(messageId, command, body)
	replArr, err := SendReadOnlyUDP(hexMessage, ip, conn)

	if err != nil {
		return "", err
	}
	if len(replArr) == 0 {
		fmt.Printf("Not able to read hex reply, continuing...")
		replyHex = "9999"
		return replyHex, err
	}
	repl := replArr[0] //should only get one reply packet back
	index := 8 + 4     //skip header(8) plus the register address(4)
	if len(repl.Data) >= index+4 {
		replyHex = fmt.Sprintf("%x", repl.Data[index:index+4]) //will be read back in the same order as registerlist
	} else {
		replyHex = "0000"
	}
	return replyHex, err
}

// takes a body string in hex, calculates the size and then returns the message prepended with the header
// depreciated
func (camera Camera) WriteMessage(messageId, command, body string) (messageWithHeader string) {
	controlRegister := "" //regBank.Auth.Address + regBank.Auth.Value
	body = strings.ReplaceAll(controlRegister+body, " ", "")
	if command == "80" || command == "84" {
		body = body + "00000004" //hardcoded for 16MP cameras that require you you say how many bytes you want to get back at the end of the req
	}
	size := fmt.Sprintf("%04x", len(body)/2)
	header := "420100" + command + size + "00" + messageId //writeMemory=86 writeRegister=82 (need to write memory before register)
	messageWithHeader = header + body
	return messageWithHeader
}

// takes a body string in hex, calculates the size and then returns the message prepended with the header
// no non-hex characters allowed as input
// messageId needs to be 2 digit hex string
// command "82"=write and "80"=read
func (camera Camera) FormatMessage(messageId int, command, body string) (messageWithHeader string) {
	messageIdHex := fmt.Sprintf("%02x", messageId)
	//	command := "82" //default write message
	//	if !strings.Contains(body, "=") {
	//		command = "80" //must be a read only message if there is no = sign
	//	}
	controlRegister := "" //regBank.Auth.Address + regBank.Auth.Value
	body = strings.ReplaceAll(controlRegister+body, " ", "")
	fmt.Printf("body=%v message size=%v\n", body, len(body)/2)
	size := fmt.Sprintf("%04x", len(body)/2)                  //calculate message size for body
	header := "420100" + command + size + "00" + messageIdHex //writeMemory=86 writeRegister=82 (need to write memory before register)
	messageWithHeader = header + body
	return messageWithHeader
}

// command is 82=registerWrite 86=memoryWrite 80=registerRead 84=memoryRead
func (camera Camera) UdpSend(command, multiMessage string, conn *net.UDPConn) (multiResponse [][]byte, err error) {
	regBank := camera.RegisterBank
	raddr := camera.CameraIp
	multiMessage = strings.ReplaceAll(multiMessage, " ", "")
	arr := strings.Split(conn.LocalAddr().String(), ":")
	if len(arr) != 2 {
		return nil, errors.New("bad local address (:port missing)")
	}
	lport, err := strconv.Atoi(arr[1])
	if err != nil {
		return nil, err
	}
	raddrPtr := net.UDPAddr{IP: net.ParseIP(raddr), Port: lport} //GVCP_PORT
	messageArr := strings.Split(multiMessage, ",")
	multiResponse = make([][]byte, len(messageArr))
	for index, message := range messageArr {
		size := fmt.Sprintf("%04x", len(message)/2)
		messageId := fmt.Sprintf("%04d", index+1)       //extremely important to update messageId (at least for Basler writes)
		header := "420100" + command + size + messageId //writeMemory=86 writeRegister=82 (need to write memory before register)
		message = header + message

		data, err := hex.DecodeString(message)
		if err != nil {
			panic(err)
		}
		count, err := conn.WriteToUDP(data, &raddrPtr) //write
		if err != nil {
			fmt.Printf("ERROR: to=%v count=%v err=%v\n", raddrPtr.String(), count, err)
			return nil, err
		}
		buffer := make([]byte, MAX_MTU) //like 9000 because that is over max packet size
		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			nRead, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				break
			}
			fmt.Printf("packet-received: bytes=%d from=%s\n", nRead, addr.String())
			hexBuffer := hex.EncodeToString(buffer)
			readCommand := "80"
			if command == readCommand {
				headerHexSize, registerHexSize := 16, 8 //response has 8 byte header (16 char in hex)
				for i := headerHexSize; i < nRead*2; i += registerHexSize {
					registerQuery := message[i : i+registerHexSize]
					name := regBank.GetName(registerQuery)
					val := hexBuffer[i : i+registerHexSize]
					easyVal := string(val)
					intVal, err := strconv.ParseUint(string(val), 16, 64) //hex2int
					if err == nil {
						easyVal = strconv.Itoa(int(intVal))
					}
					if len(name) >= 18 && name[:18] == "STREAM_DESTINATION" {
						easyVal = Hex2Ip(string(val))
					}
					multiResponse[index] = append(multiResponse[index], []byte(registerQuery+" "+val+" "+easyVal+" "+name)...)
				}
			} else {
				multiResponse[index] = append(multiResponse[index], hexBuffer[:nRead*2]...)
			}
		}
	}
	return multiResponse, err
}
func Ip2Hex(ip string) string {
	var long uint32
	//169.254.248.236 = a9fef8ec
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	hex := fmt.Sprintf("%08x", long) //int2hex
	return hex
}

// ToDots converts a uint32 to a IPv4 Dotted notation
//
// About 10x faster than doing something with fmt.Sprintf
// one allocation per call.
//
// Based on golang's net/IP.String()
// https://golang.org/src/net/ip.go?s=7645:7673#L281
func ToDots(p4 uint32) string {
	const maxIPv4StringLen = len("255.255.255.255")
	b := make([]byte, maxIPv4StringLen)

	n := ubtoa(b, 0, byte(p4>>24))
	b[n] = '.'
	n++

	n += ubtoa(b, n, byte((p4>>16)&0xFF))
	b[n] = '.'
	n++

	n += ubtoa(b, n, byte((p4>>8)&0xFF))
	b[n] = '.'
	n++

	n += ubtoa(b, n, byte(p4&0xFF))
	return string(b[:n])
}

// from
// https://golang.org/src/net/ip.go?s=7645:7673#L281
//
// ubtoa encodes the string form of the integer v to dst[start:] and
// returns the number of bytes written to dst. The caller must ensure
// that dst has sufficient length.
func ubtoa(dst []byte, start int, v byte) int {
	if v < 10 {
		dst[start] = v + '0'
		return 1
	} else if v < 100 {
		dst[start+1] = v%10 + '0'
		dst[start] = v/10 + '0'
		return 2
	}

	dst[start+2] = v%10 + '0'
	dst[start+1] = (v/10)%10 + '0'
	dst[start] = v/100 + '0'
	return 3
}

// should be in plain 0a32df84 hex format, not 0x0a32df84
func Hex2Ip(hex string) string {
	oct1, err := strconv.ParseUint(hex[:2], 16, 8)
	if err != nil {
		return ("bad ip")
	}
	oct2, err := strconv.ParseUint(hex[2:4], 16, 8)
	if err != nil {
		return ("bad ip")
	}
	oct3, err := strconv.ParseUint(hex[4:6], 16, 8)
	if err != nil {
		return ("bad ip")
	}
	oct4, err := strconv.ParseUint(hex[6:8], 16, 8)
	if err != nil {
		return ("bad ip")
	}
	return strconv.Itoa(int(oct1)) + "." + strconv.Itoa(int(oct2)) + "." + strconv.Itoa(int(oct3)) + "." + strconv.Itoa(int(oct4))
}
func Hex2Num(hex string) uint64 {
	numberStr := strings.Replace(hex, "0x", "", -1)
	numberStr = strings.Replace(numberStr, "0X", "", -1)
	n, err := strconv.ParseUint(numberStr, 16, 64)
	if err != nil {
		fmt.Printf("error in control.Hex2Num: %v\n", err)
		panic(err)
	}
	return n
}

// This takes a register name/value string like this "Auth=1,GevSCPSPacketSize=9000,STREAM_DESTINATION=10.50.223.132,GevSCPHostPort=55555,AcquisitionStart=1"
// and converts it into a hex command string (it does not send anything to the camera though)
// also supports raw address format like R[00030204]=1
// note: if sending STREAM_DESTINATION, it should normally be set to the host ip on the same network as the cameras (ipv4 dotted notation)
// output will not include any commas
func (cam Camera) TextToHex(registerValues string) (commandCode, hexMessage string) {
	commandCode = "80" //default is to read with 80
	if registerValues != "" {
		registerValues = strings.ReplaceAll(registerValues, " ", "")
		commaArr := strings.Split(registerValues, ",")
		for _, reg := range commaArr {
			arr := strings.Split(reg, "=")
			if len(arr) == 1 {
				//if we are here then this is just a read
				address := cam.GetAddress(reg) //register
				if address == "" {
					hexValue := reg //if not a lookup name, then use the raw value passed-in (could be valid hex)
					hexMessage = hexMessage + hexValue
				} else {
					hexMessage = hexMessage + address
				}
			} else {
				commandCode = "86" //all cameras seem to save with 82 doug
				register := arr[0]
				value := arr[1]
				address := cam.GetAddress(register)
				var hexValue string
				if register == "STREAM_DESTINATION" {
					hexValue = Ip2Hex(value)
				} else {
					hex, err := ValueToHex(value)
					if err != nil {
						fmt.Printf("control.Text2Hex input error: %v value=%v\n", err, value)
					}
					hexValue = hex
				}
				hexMessage = hexMessage + address + hexValue

			}
		} //end commaArr
		hexMessage = strings.TrimLeft(hexMessage, ",") //remove leading ,
	}
	return commandCode, hexMessage
}
func PrintRegisters() {
	println()
	println("control register list:")
	rb := NewCamera("", "", 0, "") //just to get a list of registers for usage: info
	registerList := structToMap(rb.RegisterBank)
	fmt.Printf("%v\n\n", registerList)
}
func structToMap(m interface{}) (registerList []string) {
	s := reflect.ValueOf(m)
	typeOfT := s.Type()
	if typeOfT.Kind() == reflect.Ptr {
		typeOfT = typeOfT.Elem()
	}
	for i := 0; i < s.NumField(); i++ {
		key := typeOfT.Field(i).Name
		registerList = append(registerList, key)
	}
	return registerList
}
func GetIP(device string) string {
	mgmtInterface, err := net.InterfaceByName(device)
	if err != nil {
		fmt.Println("Unable to find interface for device", device)
		os.Exit(-1)
	}

	addrs, err := mgmtInterface.Addrs()
	if err != nil {
		fmt.Println("Interface has no address")
		os.Exit(-1)
	}
	//addrs=[192.168.1.1/24 fe80::e2d5:5eff:fe25:d11e/64]
	shortestIp := addrs[0].String()
	if len(addrs) > 1 {
		if len(addrs[1].String()) < len(shortestIp) {
			shortestIp = addrs[1].String()
		}
	}
	ipStr := shortestIp
	ipArr := strings.Split(shortestIp, "/")
	if len(ipArr) > 1 {
		ipStr = ipArr[0]
	}
	return ipStr
}
func GetUDPConnection(laddr string, lport int) *net.UDPConn {
	laddrPtr, err := net.ResolveUDPAddr("udp", laddr+":"+strconv.Itoa(lport))
	if err != nil {
		println("error net.ResolveUDPAddr", laddr+":"+strconv.Itoa(lport))

		log.Fatal(err)
	}
	var conn *net.UDPConn
	conn, err = net.ListenUDP("udp", laddrPtr)
	if err != nil {
		println("error net.ListenUDP", laddrPtr)
		log.Fatal(err)
	}
	return conn
}
func GetControlConnection(laddr string) *net.UDPConn {
	return GetUDPConnection(laddr, GVCP_PORT)
}

// This will ping all the cameras on the network and return a map of control.Camera objects
// addr will normally be 255.255.255.255 unless targeting a single camera by IPj
func GetCameraMap(controlConn *net.UDPConn, remoteAddr net.Addr) (cameraMap map[uint64]Camera, err error) {
	cameraMap = make(map[uint64]Camera) //maps IP and port to camera
	controlConn.LocalAddr().String()
	cameraReplyArr, err := GetCameras(remoteAddr, controlConn)
	if err != nil {
		panic(err)
	}
	//ModelName - Firmware - Width - Height - PixelFormat - GevSCPSPacketSize - GainAuto.tcpdump
	fmt.Printf("## CameraIp        Id        Name           ModelName   Firmware   Width Height PixelFormat GainAuto GevSCPSPacketSize GevSCPD AcquisitionMode\n")
	matchSettings := ""
	lastMatchSettings := ""

	for i, c := range cameraReplyArr {
		arr := strings.Split(controlConn.LocalAddr().String(), ":")
		if len(arr) < 2 {
			fmt.Printf("Address parsing errorinGetCameraMap arr=%v\n", arr)
		}
		justHostIp := arr[0]
		fmt.Printf("HostIp=%v JustHostIp=%v\n", controlConn.LocalAddr().String(), justHostIp)
		camera := NewCamera(justHostIp, c.CameraIp, uint32(STREAM_PORT), c.ModelName)
		//controlConn.RemoteAddr()
		localAddrArr := strings.Split(controlConn.LocalAddr().String(), ":")
		if len(localAddrArr) < 2 {
			fmt.Printf("error parsing localAddr.String() %v\n", controlConn.LocalAddr().String())
		} else {
			fmt.Printf("parsed localAddr.String() %v\n", controlConn.LocalAddr().String())
		}
		println("---------------------------------------------------------")
		ip_port := ImplodeIpPort(camera.CameraIpLong, uint32(STREAM_PORT)) //for gige
		fmt.Printf("AAAAAA %v %v %v = %v\n\n", IpStr2Long(c.CameraIp), c.CameraIp, uint32(STREAM_PORT), ip_port)

		fetchRegisters := []string{"Width", "Height", "PixelFormat", "GainAuto", "GevSCPSPacketSize", "GevSCPD", "AcquisitionMode"}

		var resultHexArr []string
		registerBatchMode := false //doug
		if registerBatchMode {
			resultHexArr, err = camera.GetCameraRegisters(fetchRegisters, controlConn)
			if err != nil {
				println("error: GetCameraRegisters", err)
			}
		} else {
			//changing to send separate calls for each register instead of sending on one batch
			for _, reg := range fetchRegisters {
				hex, err := camera.GetCameraRegister(reg, controlConn)
				if err != nil {
					println("error: GetCameraRegisters", err)
				}
				resultHexArr = append(resultHexArr, hex) //we know there will be only one result in here cause we only requested one register value (reg)
			}
		}
		if len(resultHexArr) != len(fetchRegisters) {
			fmt.Printf("%02d %-15v %-9v %-14v %-11v %v\n", i, c.CameraIp, c.Id, c.Name, c.ModelName, c.Firmware)
			fmt.Printf("Error: not all registers were found %+v\n\n\n", resultHexArr)
			cameraMap[ip_port] = camera
			continue
		} else {
			fmt.Printf("All registers were found %+v\n\n\n", resultHexArr)
		}
		PixelFormatHex := resultHexArr[2]
		PixelFormat := int(Hex2Num(PixelFormatHex))
		GainAuto := int(Hex2Num(resultHexArr[3]))
		GevSCPSPacketSizeHex := resultHexArr[4]
		fmt.Printf("GevSCPSPacketSizeHex=%v\n\n", GevSCPSPacketSizeHex)
		AcquisitionMode := int(Hex2Num(resultHexArr[6]))
		matchSettings = GevSCPSPacketSizeHex + PixelFormatHex
		if i > 0 {
			if matchSettings != lastMatchSettings {
				return nil, err
			}
		}
		lastMatchSettings = matchSettings
		GevSCPSPacketSize := Hex2Num(GevSCPSPacketSizeHex)
		fmt.Printf("GevSCPSPacketSize=%v\n\n", GevSCPSPacketSize)
		camera.GevSCPSPacketSize.Value = GevSCPSPacketSizeHex
		Width := int(Hex2Num(resultHexArr[0]))
		Height := int(Hex2Num(resultHexArr[1]))
		camera.Width = Width
		camera.Height = Height
		camera.CameraName = c.Name
		camera.OutputFormat = 0 //default should probably not debayer when writing in ListenAndWrite
		camera.PixelFormat = PixelFormat
		if PixelFormat == 20 {
			//hardcoded pixel format check for BayerRG12 - 20 (0x14) - works for basler
			camera.BitDepth = 12
		} else {
			camera.BitDepth = 8 //default

		}
		GevSCPD := Hex2Num(resultHexArr[5])
		fmt.Printf("%02d %-15v %-9v %-14v %-11v %v % 4d % 4d % 4d % 4d  % 4d % 4d % 4d\n", i, string(c.CameraIp), strings.ReplaceAll(c.Id, "\x00", ""), c.Name, c.ModelName, c.Firmware, Width, Height, PixelFormat, GainAuto, GevSCPSPacketSize, GevSCPD, AcquisitionMode)
		cameraMap[ip_port] = camera
	}
	if len(cameraMap) == 0 {
		println("no cameras connected to", controlConn.LocalAddr().String())
		os.Exit(1)
	}
	return cameraMap, err
}

func SetNice() (err error) {
	pid := syscall.Getpid()
	preNice, err := syscall.Getpriority(syscall.PRIO_PROCESS, pid)
	if err != nil {
		println("Unknown PID before", pid)
		return err
	}
	println("preNice=", preNice)
	err = syscall.Setpriority(syscall.PRIO_PROCESS, pid, -19)
	if err != nil {
		println("warning: Setpriority failed- continuing with regular nice value")
	}
	afterNice, err := syscall.Getpriority(syscall.PRIO_PROCESS, pid)
	if err != nil {
		println("Unknown PID after", pid)
		return err
	}
	println("afterNice=", afterNice)
	return err
}

func SetUDPBufferSize(streamConn *net.UDPConn) (err error) {
	udpRecBufferSize := 4000000 //4MB recieve buffer
	file, err := streamConn.File()
	if err != nil {
		fmt.Printf("can't open connection File")
		return err
	}
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, int(RCVBUF_COMMAND), udpRecBufferSize)

	if err != nil {
		streamConn.SetReadBuffer(425984) //2*212992 is the max allowed here
		println("error setting sysctl net.core.rmem_max. Try running:\nsudo setcap 'cap_net_admin=+ep' gige.linux")
		//setcap cap_net_raw+eip <application>
		//setcap cap_net_raw+ep /path/to/executable

		//Raw packet works on IP level (OSI layer 3), pcap on data link layer (OSI layer 2). So its less a performance issue and more a question of what you want to capture. If performance is your main issue search for PF_RING etc, that's what current IDS use for capturing.
		//Edit: raw packets can be either IP level (AF_INET) or data link layer (AF_PACKET), pcap might actually use raw sockets, see Does libpcap use raw sockets underneath them?

		return err
	}
	rmem, _ := syscall.GetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	fmt.Printf("RCVBUF=%v\n", rmem)
	return err
}

func ImplodeIpPort(ip, port uint32) (ip_port uint64) {
	ip_port = uint64(uint64(ip) + uint64(port)<<32) //makes a 64bit number where low 32bits are the IP and high is the port
	return
}

// If you provide a cameraIp it will return that nic interface , otherwise it returns the last nick in the list that's not localhost
func DetectInterface(cameraIp string) (device string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v", err.Error()))
		return
	}

	afterFirstRow := false
	for _, i := range ifaces {
		addr, _ := i.Addrs()
		for _, a := range addr {
			addrArr := strings.Split(a.String(), ".")
			if len(addrArr) == 4 && a.String()[:3] != "127" {
				if afterFirstRow {
					println()
				}
				afterFirstRow = true
				fmt.Printf("%v MTU=%v IP4=%v", i.Name, i.MTU, a.String())
				device = i.Name //assign device to highest device number that is IPv4 and not localhost (127)
				println("i.Name=", i.Name)
				if cameraIp != "" {
					camIpArr := strings.Split(cameraIp, ".")
					if camIpArr[0] == addrArr[0] && camIpArr[1] == addrArr[1] && camIpArr[2] == addrArr[2] {
						println("return", i.Name)
						return
					}
				}
			}
		}
	}
	return
}
func (camera Camera) SendRegisterValues(controlConn *net.UDPConn, sendAddress string, registerValue string) (sendError error) {
	msgArr := strings.Split(registerValue, ",")
	for seqId, msg := range msgArr {
		seqId += 1                       //we can't start sending messages with 0 sequence number
		_, body := camera.TextToHex(msg) //takes in comma delimeted list of commands
		command := camera.SaveCommand    //normally we need to use the default save command (except for Auth command)
		if msg == "Auth=1" || msg == "Auth=2" {
			command = "82"
		}
		hexMessage := camera.FormatMessage(seqId, command, body) //messageId is 2 digit hex
		fmt.Printf("sendAddress=%v saveCommand=%v registerValue: %v\nbody=%v\nhexMessage=%v\n", sendAddress, camera.SaveCommand, registerValue, body, hexMessage)
		replies, err := SendReadOnlyUDP(hexMessage, sendAddress, controlConn)

		if err == nil {
			fmt.Printf("replies\n")
			for i := 0; i < len(replies); i++ {
				fmt.Printf(" %d=%s data=%x\n", i, replies[i].IP, replies[i].Data)
			}
		} else {
			fmt.Printf("err=%v\n", err)
			sendError = err
			return
		}

	}
	fmt.Println()
	return
}
