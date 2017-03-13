package ptp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Constants
const (
	MagicCookie uint16 = 0xabcd // Used to filter traffic not related to subutai-p2p
	HeaderSize  int    = 18     // Size of a network header
)

// P2PMessageHeader is a header used in cross-peer packets
// Message header is appended to every packet received by TUN/TAP interface
// TODO: Remove ID and Seq
type P2PMessageHeader struct {
	Magic         uint16 // Magic cookie
	Type          uint16 // Type of a packet
	Length        uint16 // Length of a packet
	NetProto      uint16 // Protocol that was extracted from source packet (payload)
	ProxyID       uint16 // ID of a proxy peer
	SerializedLen uint16 // Length of a serialized packet
	Complete      uint16 // Whether packet truncated or not
	ID            uint16 // ID was used in previous versions
	Seq           uint16 // Seq was used in previous versions
}

// P2PMessage is a cross-peer message packet
type P2PMessage struct {
	Header *P2PMessageHeader // P2P Packet Header
	Data   []byte            // P2P Packet Payload
}

// Serialize does a header serialization
// Method return a byte slice
func (v *P2PMessageHeader) Serialize() []byte {
	resBuf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(resBuf[0:2], v.Magic)
	binary.BigEndian.PutUint16(resBuf[2:4], v.Type)
	binary.BigEndian.PutUint16(resBuf[4:6], v.Length)
	binary.BigEndian.PutUint16(resBuf[6:8], v.NetProto)
	binary.BigEndian.PutUint16(resBuf[8:10], v.ProxyID)
	binary.BigEndian.PutUint16(resBuf[10:12], v.SerializedLen)
	binary.BigEndian.PutUint16(resBuf[12:14], v.Complete)
	binary.BigEndian.PutUint16(resBuf[14:16], v.ID)
	binary.BigEndian.PutUint16(resBuf[16:18], v.Seq)
	return resBuf
}

// P2PMessageHeaderFromBytes extracts message header from received packet
// The byte slice should be provided as an input and it should be exact
// the same size as HeaderSize constant. if it's not - method will return
// an error.
// Method returns a P2PMessageHeader structure
func P2PMessageHeaderFromBytes(bytes []byte) (*P2PMessageHeader, error) {
	if len(bytes) < HeaderSize {
		return nil, errors.New("P2PMessageHeaderFromBytes_error : less then 14 bytes")
	}

	result := new(P2PMessageHeader)
	result.Magic = binary.BigEndian.Uint16(bytes[0:2])
	result.Type = binary.BigEndian.Uint16(bytes[2:4])
	result.Length = binary.BigEndian.Uint16(bytes[4:6])
	result.NetProto = binary.BigEndian.Uint16(bytes[6:8])
	result.ProxyID = binary.BigEndian.Uint16(bytes[8:10])
	result.SerializedLen = binary.BigEndian.Uint16(bytes[10:12])
	result.Complete = binary.BigEndian.Uint16(bytes[12:14])
	result.ID = binary.BigEndian.Uint16(bytes[14:16])
	result.Seq = binary.BigEndian.Uint16(bytes[16:18])
	return result, nil
}

// GetProxyAttributes returns information related to current proxy in a message header
// This method is used by proxy peers to not to parse the whole packet and just
// extract necessary information about the tunnel ID to pass traffic further
func GetProxyAttributes(bytes []byte) (uint16, uint16) {
	return binary.BigEndian.Uint16(bytes[8:10]), binary.BigEndian.Uint16(bytes[2:4])
}

// Serialize constructs a P2P message
// First it calculates the length of payload and updates Header's field
// SerializedLen. Then it serializes header and appens payload to the
// resulting byte slice
func (v *P2PMessage) Serialize() []byte {
	v.Header.SerializedLen = uint16(len(v.Data))
	Log(Trace, "--- Serialize P2PMessage header.SerializedLen : %d", v.Header.SerializedLen)
	resBuf := v.Header.Serialize()
	resBuf = append(resBuf, v.Data...)
	return resBuf
}

// P2PMessageFromBytes deserializes packet to P2PMessage
// This method will parse message header and extract payload
// from it of exact length (SerializedLen)
func P2PMessageFromBytes(bytes []byte) (*P2PMessage, error) {
	res := new(P2PMessage)
	var err error
	res.Header, err = P2PMessageHeaderFromBytes(bytes)
	if err != nil {
		return nil, err
	}
	Log(Trace, "--- P2PMessageHeaderFromBytes Length : %d, SerLen : %d", res.Header.Length, res.Header.SerializedLen)
	if res.Header.Magic != MagicCookie {
		return nil, errors.New("magic cookie not presented")
	}
	res.Data = make([]byte, res.Header.SerializedLen)
	Log(Trace, "BYTES : %s", bytes)
	copy(res.Data[:], bytes[HeaderSize:])
	Log(Trace, "res.Data : %s", res.Data)
	return res, err
}

// CreateStringP2PMessage creates a normal P2P message
func CreateStringP2PMessage(c Crypto, data string, netProto uint16) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeString)
	msg.Header.NetProto = netProto
	msg.Header.Length = uint16(len(data))
	msg.Header.Complete = 1
	if c.Active {
		var err error
		msg.Data, err = c.Encrypt(c.ActiveKey.Key, []byte(data))
		if err != nil {
			Log(Error, "Failed to encrypt data")
		}
	} else {
		msg.Data = []byte(data)
	}
	return msg
}

// CreatePingP2PMessage creates a PING message
func CreatePingP2PMessage() *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypePing)
	msg.Header.NetProto = 0
	msg.Header.Length = uint16(len("1"))
	msg.Header.Complete = 1
	msg.Header.ID = 0
	msg.Data = []byte("1")
	return msg
}

// CreateConfP2PMessage creates a confirmation message
func CreateConfP2PMessage(id, seq uint16) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeConf)
	msg.Header.NetProto = 0
	msg.Header.Length = uint16(len("1"))
	msg.Header.Complete = 1
	msg.Header.ID = id
	msg.Header.Seq = seq
	msg.Data = []byte("1")
	return msg
}

// CreateXpeerPingMessage creates a cross-peer PING message
func CreateXpeerPingMessage(pt PingType, hw string) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeXpeerPing)
	msg.Header.NetProto = uint16(pt)
	msg.Header.Length = uint16(len(hw))
	msg.Header.Complete = 1
	msg.Header.ID = 0
	msg.Data = []byte(hw)
	return msg
}

// CreateIntroP2PMessage creates a handshake response
func CreateIntroP2PMessage(c Crypto, data string, netProto uint16) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeIntro)
	msg.Header.NetProto = netProto
	msg.Header.Length = uint16(len(data))
	msg.Header.Complete = 1
	msg.Header.ID = 0
	if c.Active {
		var err error
		msg.Data, err = c.Encrypt(c.ActiveKey.Key, []byte(data))
		if err != nil {
			Log(Error, "Failed to encrypt data")
		}
	} else {
		msg.Data = []byte(data)
	}
	return msg
}

// CreateIntroRequest creates a handshake request
func CreateIntroRequest(c Crypto, id string) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeIntroReq)
	msg.Header.NetProto = 0
	msg.Header.Length = uint16(len(id))
	msg.Header.Complete = 1
	msg.Header.ID = 0
	if c.Active {
		var err error
		msg.Data, err = c.Encrypt(c.ActiveKey.Key, []byte(id))
		if err != nil {
			Log(Error, "Failed to encrypt data")
		}
	} else {
		msg.Data = []byte(id)
	}
	return msg
}

// CreateNencP2PMessage creates a normal message with encryption
func CreateNencP2PMessage(c Crypto, data []byte, netProto, complete, id, seq uint16) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeNenc)
	msg.Header.NetProto = netProto
	msg.Header.Length = uint16(len(data))
	msg.Header.Complete = complete
	msg.Header.ID = id
	msg.Header.Seq = seq
	if c.Active {
		var err error
		msg.Data, err = c.Encrypt(c.ActiveKey.Key, data)
		if err != nil {
			Log(Error, "Failed to encrypt data")
		}
	} else {
		msg.Data = data
	}
	return msg
}

// CreateTestP2PMessage creates a test cross-peer message
func CreateTestP2PMessage(c Crypto, data string, netProto uint16) *P2PMessage {
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeTest)
	msg.Header.NetProto = netProto
	msg.Header.Length = uint16(len(data))
	msg.Header.Complete = 1
	msg.Header.ID = 0
	if c.Active {
		var err error
		msg.Data, err = c.Encrypt(c.ActiveKey.Key, []byte(data))
		if err != nil {
			Log(Error, "Failed to encrypt data")
		}
	} else {
		msg.Data = []byte(data)
	}
	return msg
}

// CreateProxyP2PMessage creates a proxy message
func CreateProxyP2PMessage(id int, data string, netProto uint16) *P2PMessage {
	// We don't need to encrypt this message
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeProxy)
	msg.Header.NetProto = netProto
	msg.Header.Length = uint16(len(data))
	msg.Header.Complete = 1
	msg.Header.ProxyID = uint16(id)
	msg.Header.ID = 0
	msg.Data = []byte(data)
	return msg
}

// CreateBadTunnelP2PMessage creates a badtunnel message
func CreateBadTunnelP2PMessage(id int, netProto uint16) *P2PMessage {
	data := "rem"
	msg := new(P2PMessage)
	msg.Header = new(P2PMessageHeader)
	msg.Header.Magic = MagicCookie
	msg.Header.Type = uint16(MsgTypeBadTun)
	msg.Header.NetProto = netProto
	msg.Header.Length = uint16(len(data))
	msg.Header.ProxyID = uint16(id)
	msg.Header.Complete = 1
	msg.Header.ID = 0
	msg.Data = []byte(data)
	return msg
}

// Network is a peer-to-peer network subsystem
type Network struct {
	host     string
	port     int
	addr     *net.UDPAddr
	conn     *net.UDPConn
	inBuffer [4096]byte
	disposed bool
}

// Stop will terminate packet reader
func (uc *Network) Stop() {
	uc.disposed = true
}

// Disposed returns whether service is willing to stop or not
func (uc *Network) Disposed() bool {
	return uc.disposed
}

// Addr returns assigned address
func (uc *Network) Addr() *net.UDPAddr {
	return uc.addr
}

// Init creates a UDP connection with specified host and port
func (uc *Network) Init(host string, port int) error {
	var err error
	uc.host = host
	uc.port = port
	uc.disposed = true

	//todo check if we need Host and Port
	uc.addr, err = net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	uc.conn, err = net.ListenUDP("udp", uc.addr)
	if err != nil {
		return err
	}
	uc.disposed = false
	return nil
}

// GetPort returns a port assigned
func (uc *Network) GetPort() int {
	addr, _ := net.ResolveUDPAddr("udp", uc.conn.LocalAddr().String())
	return addr.Port
}

// UDPReceivedCallback is executed when message is received
type UDPReceivedCallback func(count int, src_addr *net.UDPAddr, err error, buff []byte)

// Listen is a main listener of a network traffic
func (uc *Network) Listen(receivedCallback UDPReceivedCallback) {
	for !uc.Disposed() {
		n, src, err := uc.conn.ReadFromUDP(uc.inBuffer[:])
		receivedCallback(n, src, err, uc.inBuffer[:])
	}
	Log(Info, "Stopping UDP Listener")
}

// Bind is depricated
// TODO: Remove bind
func (uc *Network) Bind(addr *net.UDPAddr, localAddr *net.UDPAddr) {

}

// SendMessage sends message over p2p network
// P2PMessage will be serialized and written to a network connection interface
// pointing to a dstAddr as a destination
// Will return the amount of bytes written and any errors or nil if
// everything went well
func (uc *Network) SendMessage(msg *P2PMessage, dstAddr *net.UDPAddr) (int, error) {
	n, err := uc.conn.WriteToUDP(msg.Serialize(), dstAddr)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// SendRawBytes sends bytes over network
// This method is similar to SendMessage, but it takes a byte slice as
// an argument instead of P2PMessage
func (uc *Network) SendRawBytes(bytes []byte, dstAddr *net.UDPAddr) (int, error) {
	n, err := uc.conn.WriteToUDP(bytes, dstAddr)
	if err != nil {
		return 0, err
	}
	return n, nil
}
