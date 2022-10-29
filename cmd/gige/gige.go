package main

//need to increase udp buffers on linux from defaults
//sudo setcap 'cap_net_admin=+ep' gige-Pix.linux
import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/disintegration/imaging"
	"github.com/dougwatson/gige/pkg/control"
	"github.com/dougwatson/gige/pkg/mmjpeg"
	"github.com/dougwatson/gige/pkg/stream"
	"github.com/gen2brain/x264-go"
	"golang.org/x/image/bmp"
)

const STREAM_PORT_NUM = 55555
const IP_HEADER_SIZE = 20
const UDP_HEADER_SIZE = 8

var (
	registerValue = flag.String("control", "", "register name like: Width and optional value (for writing) like: Width=1000. R[00030204]=1000")
	device        = flag.String("i", "", "provide the local network interface (like en9 or eth0. Otherwise it will select the highest IPv4 device")
	cameraIp      = flag.String("a", "255.255.255.255", "remote ip address")
	record        = flag.Bool("record", false, "start stream recording (will require the AcquisitionStart control trigger)- it continiously saves image frames to png files")
	path          = flag.String("path", ".", "path for output png image files")
	limit         = flag.Int("limit", -1, "Default -1 is for reading unlimited packets")
	resize        = flag.Int("resize", 0, "resize the width of the image to 'resize' number of pixels if the value is greater than zero. Width will resize proportially ")
	h264          = flag.Bool("h264", false, "use high efficiency 264 video format. to view, you will need to wrap in mp4 with ffmpeg or use the mpv program")
)

func main() {
	numArgs := len(os.Args)
	controlArgNum := 0
	for i, arg := range os.Args {
		if arg == "-control" {
			controlArgNum = i
		}
	}
	firstCharIsComma := len(os.Args) > controlArgNum+1 && os.Args[controlArgNum+1][0] == ','
	lastCharIsComma := len(os.Args) > controlArgNum+1 && os.Args[controlArgNum+1][len(os.Args[controlArgNum+1])-1] == ','
	if os.Args[numArgs-1] == "-control" || firstCharIsComma || lastCharIsComma {
		control.PrintRegisters() //this helps when building a command up to see the list of register options. trailing comma works too
		os.Exit(1)
	}
	flag.Parse() // Parse command line arguments

	if *device == "" {
		*device = control.DetectInterface(*cameraIp)
		fmt.Printf("*\n")
		println("DEVICE=", *device)
		if *device == "" {
			println("Unable to detect device. Please provide the network device with the -d flag. Check ifconfig to find the network that your ip camera is connected to.")
			println("ex: -d en9")
			println()
			flag.PrintDefaults()
			println()
			os.Exit(1)
		}

	}

	hostIp := control.GetIP(*device)
	q := net.ParseIP(*cameraIp)
	cameraAddr := &net.IPAddr{q, ""}                    //could be 255.255.255.255
	controlConn := control.GetControlConnection(hostIp) //server listening on 3956

	settingsError := false
	cameraMap, err := control.GetCameraMap(controlConn, cameraAddr)
	if err != nil {
		fmt.Printf("err=", err)
	}
	fmt.Printf("cameraMap=%v\n", cameraMap)
	if *registerValue == "" && *record {
		//AcquisitionMode=0, single-shot
		//AcquisitionMode=2 continious
		//you can add AcquisitionMode=0 if you need to take a single shot
		//		*registerValue = "Auth=2,GevSCPSPacketSize=9000,STREAM_DESTINATION=" + hostIp + ",GevSCPHostPort=" + fmt.Sprint(PORT_NUM) + ",AcquisitionStart=1"
		*registerValue = "Auth=2,GevSCPSPacketSize=8192,GevHeartbeatTimeout=4000,STREAM_DESTINATION=" + hostIp + ",GevSCPHostPort=" + fmt.Sprint(STREAM_PORT_NUM) + ",AcquisitionStart=1"
	}
	//create an empty camera object so we can load the firstCamera in here
	//firstCamera := control.NewCamera(hostIp, "0.0.0.0", uint32(STREAM_PORT_NUM), "foo") //initialize empty camera object
	var baseCamera control.Camera
	var cameraIds []uint64
	for cameraId, cam := range cameraMap {
		//if baseCamera.CameraIpLong == 0 {
		baseCamera = cam
		fmt.Printf("ip=%v stream_port=%v GevSCPSPacketSize=%v cameraId=%v\n", cam.CameraIpLong, cam.CameraStreamSourcePort, cam.GevSCPSPacketSize.Value, cameraId)
		cameraIds = append(cameraIds, cameraId)
		//}
		//break
	}
	sendAddress := "255.255.255.255"

	if *registerValue != "" {
		err := baseCamera.SendRegisterValues(controlConn, sendAddress, *registerValue)
		if err != nil {
			println("error sending register values", err)
		}
	}

	fmt.Printf("width=%v height=%v bitDepth=%v gamma=%v MTU=%v\n", baseCamera.Width, baseCamera.Height, baseCamera.BitDepth, baseCamera.Gamma, baseCamera.MTU)
	baseCamera.MTU = 8192 //lkudge- we should read this out from the camera
	//if baseCamera.MTU != 8192 {
	println("warning: please make sure camera MTU setting is 8192. Try running: arv-tool-0.8 control GevSCPSPacketSize to verify")
	//}
	if *record {
		if settingsError {
			println("error: recording GevSCPSPacketSize/PixelFormat settings don't match between cameras")
			os.Exit(1)
		}
		/*
			var baseCamera = control.Camera{
				ModelName:    "cam1",
				HostIp:       hostIp,
				HostPort:     STREAM_PORT_NUM,   //55555
				MTU:          8192,              //firstCamera.MTU,   //arv-tool-0.8 control GevSCPSPacketSize=8192
				Width:        firstCamera.Width, //arv-tool-0.8 control Width Height
				Height:       firstCamera.Height,
				BitDepth:     firstCamera.BitDepth,     //8
				Gamma:        1.0,                      //firstCamera.Gamma,        //1.0
				OutputFormat: firstCamera.OutputFormat, //0
			}
		*/
		go baseCamera.BroadcastHeartbeat(controlConn, 1*time.Second) //this keeps the cameras free-run mode going. It will end when the listener exits
		queueSize := 40
		frameChannelMap := stream.RecordFrames(baseCamera, queueSize, *limit)

		for _, id := range cameraIds {
			frameChannelMap[id] = make(chan stream.Frame, queueSize)

		}
		println("[len(frameChannelMap)]=", len(frameChannelMap))

		for n, id := range cameraIds {
			frameChannel := frameChannelMap[id]
			astream := mmjpeg.NewStream(100 * time.Millisecond)
			fmt.Printf("%v connect to localhost:8801\n", time.Now())
			go func(n int, astream *mmjpeg.Stream) {
				err := http.ListenAndServe(":"+strconv.Itoa(8880+n), astream) //port 8800, 8801, ...
				if err != nil {
					fmt.Printf("%v webserver closed\n", time.Now())
				}
			}(n, astream)

			go processFrames(frameChannel, baseCamera, astream)
			//time.Sleep(30)
			println("---------------next---------------", n, id)
			//break
		}
		select {} //block forever
	}

}
func processFrames(frameChannel chan stream.Frame, baseCamera control.Camera, astream *mmjpeg.Stream) {
	enc := &png.Encoder{CompressionLevel: png.NoCompression}
	var enc264 *x264.Encoder

	buf := new(bytes.Buffer)
	bayerImg := image.NewGray(image.Rect(0, 0, baseCamera.Width, baseCamera.Height))
	counter := 0
	var filename string
	var file *os.File
	for {
		oTime := time.Now()
		frame := <-frameChannel //this will only record from 1 camera. to record from more than 1 camera, you need to spawn a new goroutine for each
		fmt.Printf("%v frameChanel read time=%v len(frameChannel)=%v cap=%v\n", frame.CameraIp, time.Since(oTime), len(frameChannel), cap(frameChannel))
		bayerImg.Pix = frame.PixelData //put raw pixels into imageGray. here it is bayered still
		start := time.Now()
		//http://www.ece.ualberta.ca/~elliott/ee552/studentAppNotes/2003_w/misc/bmp_file_format/bmp_file_format.htm
		err := bmp.Encode(buf, bayerImg) //10 ms to convert 16MP Gray RGGB to png buffer with no compression
		if err != nil {
			log.Fatalf("failed to encode image: %v", err)
		}
		fmt.Printf("encode time=%v\n", time.Since(start))
		start = time.Now()

		img, err := imaging.Decode(buf)
		if err != nil {
			log.Fatalf("failed to decode image: %v", err)
		}
		fmt.Printf("dencode time=%v\n", time.Since(start))
		buf.Reset()

		switch img.(type) {
		case *image.RGBA:
			println("img in an *image.RGBA")
		case *image.NRGBA:
			println("img in an *image.NRBGA")
		case *image.Gray:
			println("img in an *image.Gray")
		case image.Image:
			println("img in an image.Image")
		default:
			println("default")
		}
		var thumb image.Image
		start = time.Now()
		if *resize > 0 {
			thumb = imaging.Resize(img, *resize, 0, imaging.Lanczos)
		} else {
			thumb = img
		}
		fmt.Printf("resize time=%v\n", time.Since(start))

		println("=============")
		fmt.Printf("thumb=%v\n", thumb.Bounds().Dx())
		start = time.Now()
		enc.Encode(buf, thumb) //was img//could have also used gocv.IMEncode(".png",img) //Encode takes 5ms on macbook for raw bayer image
		fmt.Printf("encode thumb time=%v\n", time.Since(start))
		t := time.Now()
		fullPath := *path + "/" + fmt.Sprint(t.Day()) + "/" + fmt.Sprint(t.Hour()) //need to change stream_test.go to find these files before I can impliment
		name := fullPath + "/" + baseCamera.ModelName + "-" + strconv.FormatUint(frame.CameraId, 10) + "." + fmt.Sprintf("%05d", frame.FrameNumber) + ".png"

		err = os.MkdirAll(fmt.Sprint(t.Day())+"/"+fmt.Sprint(t.Hour()), 0777)
		if err != nil {
			println("Make directory error", err.Error())
		}
		fmt.Printf("mkdir time=%v\n", time.Since(t))
		if *h264 {
			if counter%600 == 0 {
				println("HEREcounter")
				if enc264 != nil {
					enc264.Flush()
					enc264.Close()
					file.Close()
					println("DONE writing mp4///////////////////////////////////////////////counter=", counter, "filename=", filename)
				}
				//start a new mp4 file every 10 minutes (600 frames actually)
				filename = frame.CameraIp + "-" + strconv.Itoa(counter) + ".264" //need to wrap it in mp4 somehow if you want playback in browser, otherwise need to use mpv program
				start = time.Now()
				file, enc264 = newMp4(filename, 5320, 3032) //frame.Width, frame.Height)
				fmt.Printf("S///////////////////////////////////////////////////////////////// newMp4 duration=%v\n", time.Since(start))
			}
			start = time.Now()
			err = enc264.Encode(img)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mp4encode %v\n", err.Error())
			}
			fmt.Printf("::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::")
			fmt.Printf("S- enc.Encode duration=%v\n", time.Since(start))
			println("::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::")
			print(".") //print a dot fo reach file written to disk
		} else {
			go ioutil.WriteFile(name, buf.Bytes(), 0777) //gocv.IMWrite(aname, hsvMat) //3 ms on macbook
			print(",")                                   //print a comma fo reach file written to disk
		}
		start = time.Now()
		astream.UpdateJPEG(buf.Bytes())
		fmt.Printf("astream time=%v\n", time.Since(start))
		buf.Reset()
		fmt.Printf("overall time=%v\n", time.Since(oTime))
		counter++
	}
}

// ImageToRGBA convert image.Image to image.RGBA
func imageToRGBA(im image.Image) *image.RGBA {
	dst := image.NewRGBA(im.Bounds())
	draw.Draw(dst, im.Bounds(), im, im.Bounds().Min, draw.Src)
	return dst
}
func newMp4(filename string, width, height int) (file *os.File, enc *x264.Encoder) {
	var err error
	file, err = os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	opts := &x264.Options{
		Width:     width, //img.Bounds().Dx()
		Height:    height,
		FrameRate: 5,
		Tune:      "zerolatency",
		Preset:    "ultrafast",
		Profile:   "baseline",
		LogLevel:  x264.LogError,
	}
	enc, err = x264.NewEncoder(file, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	return file, enc
}
