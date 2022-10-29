package stream

//important for macbooks
//$ sysctl net.inet.udp.recvspace
//net.inet.tcp.recvspace: 131072
//sudo sysctl -w net.inet.udp.recvspace=7100000
//$ sysctl net.inet.udp.recvspace
//net.inet.udp.recvspace: 7100000

//this though was already at about max
//sudo sysctl -w kern.ipc.maxsockbuf=8000000
//this iincreases mac udp buffer space

//for linux run:
//sudo setcap 'cap_net_admin=+ep' gige.linux

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/dougwatson/gige/pkg/control"
)

const IP_HEADER_SIZE = 20
const UDP_HEADER_SIZE = 8

//const MTU = 8192                                                 //16MP basler cameras cannot go all the way up to 9000
//const MAX_IMAGE_PAYLOAD = MTU - IP_HEADER_SIZE - UDP_HEADER_SIZE //8192-28=8164

type Frame struct {
	CameraId    uint64 //ip_port
	CameraName  string
	CameraIp    string
	Width       int
	Height      int
	FrameNumber uint64 //auto increment by camera. A global frame id is CameraId+FrameNumber
	PixelData   []byte //check Camera.PixelFormat to know if you use 1 byte per pixel or 2 (or other)
	//	Image  *image.Gray
}

// limit -1 means record unlimited frames
// queue size 100 means you need to store 100*16MB for 16MP camera (1.6GB)
func RecordFrames(cam control.Camera, queueSize int, limit int) (frameChannelMap map[uint64]chan Frame) {
	frameChannelMap = map[uint64]chan Frame{}
	go recorder(cam, frameChannelMap, queueSize, limit)
	return
}

// The output channel will contain cameraId and the byte slice of image data for each frame.
// The cameraId is the ipaddress (int32) and stream source port (int32) of the camera an an int64.
// frameByteCount=width*height*bytesPerPixel
// The hot-loop in this function must be fast to avoid dropping UDP packets. Also don't run more than one instance of this per PID
func recorder(cam control.Camera, frameChannelMap map[uint64]chan Frame, queueSize int, limit int) (err error) {
	frameByteCount := cam.Width * cam.Height * cam.BitDepth / 8
	fmt.Printf("recorder cam.HostIp=%v cam.HostPort=%v\n", cam.HostIp, cam.HostPort)
	streamConn := control.GetUDPConnection(cam.HostIp, cam.HostPort) //start each recoder on it's own UDP port
	defer streamConn.Close()
	err = control.SetUDPBufferSize(streamConn)
	if err != nil {
		println("could not SetUDPBufferSize err=%v\n\n", err)
	}

	_ = os.Remove("streamRecord.txt")
	file, err := os.Create("streamRecord.txt")
	if err != nil {
		println("error opening output file streamRecord.txt")
		panic(err.Error())
	}
	defer file.Close()
	fmt.Fprintf(file, "ip_port,pictureMapCount,packetNum,actualSize,maxImagePayload*packetNum,difference\n")
	maxImagePayload := cam.MTU - IP_HEADER_SIZE - UDP_HEADER_SIZE
	println("maxImagePayload=", maxImagePayload, "cameraMTU=", cam.MTU, "frameByteCount=", frameByteCount)
	buf := make([]byte, maxImagePayload)
	pictureMap := make(map[uint64][]byte) //127.0.0.2:4444 whatever ip and port the camera sends on (not what port it sends to)
	loop := 0
	timeoutSeconds := uint8(20) //was 20
	mx := &sync.Mutex{}
	frameNumber := make(map[uint64]uint64)
	//var localAddrArr []string
	localPort := 55555
	//udp packet read hot loop
	for {
		if loop > 0 {
			timeoutSeconds = 1
		}
		loop++
		n, _, packetType, addr, err := ReadImagePacket(streamConn, timeoutSeconds, buf) //1-560 or 563/1120
		if err != nil {
			println("ReadImagePacket error:", err)
			break
		}
		if packetType == 3 {
			//localAddrArr = strings.Split(streamConn.LocalAddr().String(), ":")
			//localPort, err := strconv.Atoi(localAddrArr[1])
			//if err != nil {
			//	println("error parsing localPort", localAddrArr[1], err)
			//}

			ip_port := control.ImplodeIpPort(ip2long(addr.IP), uint32(localPort))
			_, ok := pictureMap[ip_port]
			if !ok {
				fmt.Printf("addr.IP=%v addr.Port=%v ip2long(addr.IP)=%v uint32(addr.Port)=%v\n", addr.IP, localPort, ip2long(addr.IP), uint32(localPort))
				pixels := make([]byte, 0, frameByteCount) // initialize new map entry. this will happen only once per camera and is set to len(picture. it gets reused on future frame reads
				pictureMap[ip_port] = pixels
			}
			num := min(n, frameByteCount-len(pictureMap[ip_port])+8)         //+8 because you don't get picture data until you have passed the header
			pictureMap[ip_port] = append(pictureMap[ip_port], buf[8:num]...) //packetNum-1 because picture slice is zero indexed but packet numbers are 1 indexed

			if n < maxImagePayload {
				//if we read less than a full packet of image data, that means this is the last packet for the frame. time to write a png
				mx.Lock()
				myFrame := Frame{CameraId: ip_port, CameraName: cam.CameraName, CameraIp: addr.IP.String(), Width: cam.Width, Height: cam.Height, FrameNumber: frameNumber[ip_port], PixelData: pictureMap[ip_port]} //ip_port is the cameraId
				frameNumber[ip_port]++
				mx.Unlock()
				if frameChannelMap[ip_port] == nil {
					fmt.Printf("make chan Frame for %v\n", ip_port)
					frameChannelMap[ip_port] = make(chan Frame, queueSize) //first time seeing this camera, make a new buffered Frame channel for it
				}
				fmt.Printf("Frame for %v\n", ip_port)
				select {
				case frameChannelMap[ip_port] <- myFrame: // Put frame in the channel unless it is full
				default:
					fmt.Printf("\033[1;31m frameChannelMap[%v] %v full. Discarding value\033[0m", ip_port, cam.CameraIp) //red - this means you are loosing packets
				}
				pictureMap[ip_port] = pictureMap[ip_port][:0] //truncate image data to prepare for next frame
				if limit == int(frameNumber[ip_port]) {
					return err
				}
			}
		}
	}
	return err
}

// If timeoutSeconds is >0 this will timeout if no frames are recieved in that duration
func ReadImagePacket(connection *net.UDPConn, timeoutSeconds uint8, b []byte) (n, packetNum int, packetType byte, addr *net.UDPAddr, err error) {
	if timeoutSeconds > 0 {
		connection.SetReadDeadline(time.Now().Add(time.Duration(timeoutSeconds) * time.Second))
	}
	n, addr, err = connection.ReadFromUDP(b)
	if err != nil {
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			return 0, 0, 0, nil, fmt.Errorf("error: timeout %v", e)
		}
		println("error reading UDP:", err)
	}
	header := b[:8]
	packetType = header[4]
	packetNum = int(binary.BigEndian.Uint16(header[6:8]))
	return n, packetNum, packetType, addr, err
}

// returns smaller of the 2 numbers
func minByte(a, b uint8) uint8 {
	if a < b {
		return a
	}
	return b
}
func minByte16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func ip2long(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
func ExplodeIpPort(ip_port uint64) (ip, port uint32) {
	ip = uint32(ip_port & 0xFFFFFFFF)
	port = uint32(ip_port >> 32)
	return
}
