package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	deviceName := flag.String("device", "", "device name, if there is no device set, a list of all devices is printed")
	discover := flag.Bool("d", false, "send also a discover message discover, after 1 sec.")
	flag.Parse()

	if *deviceName != "" {
		handle, err := pcap.OpenLive(*deviceName, 65536, true, pcap.BlockForever)
		if err != nil {
			fmt.Println("Error during openning device name", *deviceName, " :", err)
			return
		}
		fmt.Println("Analyze DHCP packets on device", *deviceName)
		stop := make(chan struct{})
		defer handle.Close()
		go readDHCP(handle, stop)
		if *discover {
			time.Sleep(time.Second)
			go sendDiscover(handle, *deviceName)
		}
		defer close(stop)
		<-stop
	} else {
		listDevicesNet()

		fmt.Println("\nType -h for usage help.")
	}
}

func listDevicesNet() {
	interfaces, err := net.Interfaces()
	if err == nil {
		fmt.Println("All available devices")
		for _, device := range interfaces {
			fmt.Printf("%-20s", device.Name)
			fmt.Printf("%-20s", device.HardwareAddr)

			addresses, _ := device.Addrs()
			if len(addresses) > 0 {
				addrs := make([]string, 0)
				for _, address := range addresses {
					addrs = append(addrs, address.String())
				}
				fmt.Print(" : ", strings.Join(addrs, ","))
			} else {
				fmt.Print(" : <none>")
			}
			fmt.Print(" ")
			fmt.Print(device.Flags)
			fmt.Print("\n")
		}
	} else {
		fmt.Println("Error during listing all network devices :", err)
	}
}
func readDHCP(handle *pcap.Handle, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:

			layer := packet.Layer(layers.LayerTypeDHCPv4)

			if layer == nil {
				continue
			}

			packet := layer.(*layers.DHCPv4)

			fmt.Println(getDHCPPacketInfo(*packet))
		}
	}
}

func getDHCPPacketInfo(packet layers.DHCPv4) string {
	info := fmt.Sprintln(packet.Operation.String(), "from", packet.ClientIP.String(), "/", packet.ClientHWAddr.String())

	for _, option := range packet.Options {
		info += fmt.Sprintf("%2s%s\n", "", option.String())
	}

	clientIP := packet.YourClientIP.String()

	if clientIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "ClientIP", clientIP)
	}

	nextServerIP := packet.NextServerIP.String()

	if nextServerIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "ServerIP", nextServerIP)
	}

	relayAgentIP := packet.RelayAgentIP.String()

	if relayAgentIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "RelayAgentIP", relayAgentIP)
	}

	info += fmt.Sprintf("%2s%s(%v)\n", "", "Xid", packet.Xid)

	return info
}
func sendDiscover(handle *pcap.Handle, deviceName string) error {
	hostname, _ := os.Hostname()
	smac := getMacAddr(deviceName)
	hw, err := net.ParseMAC(smac)
	if err != nil {
		return err
	}
	srcIP := net.ParseIP("0.0.0.0")

	//eth layer
	eth := &layers.Ethernet{}
	eth.SrcMAC = hw
	eth.DstMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	eth.EthernetType = layers.EthernetTypeIPv4

	//ip layer
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolUDP
	ip.TTL = 64
	ip.SrcIP = srcIP
	ip.DstIP = net.ParseIP("255.255.255.255")

	//udp layer
	udp := &layers.UDP{
		SrcPort:  68,
		DstPort:  67,
		Length:   0,
		Checksum: 0,
	}

	//dhcpv4 layer and options
	dhcp4 := &layers.DHCPv4{}
	dhcp4.Flags = 0x0000
	dhcp4.Operation = layers.DHCPOpRequest
	dhcp4.HardwareType = layers.LinkTypeEthernet
	dhcp4.Xid = uint32(rand.Int31())
	dhcp4.ClientIP = net.ParseIP("0.0.0.0")
	dhcp4.ClientHWAddr = hw
	hn := []byte(hostname)

	//dhcpv4 options
	dhcp4Opts := []layers.DHCPOption{
		{
			Type:   layers.DHCPOptMessageType,
			Length: 1,
			Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
		},
		{
			Type:   layers.DHCPOptRequestIP,
			Length: 4,
			Data:   net.ParseIP("0.0.0.0").To4(),
		},
		{
			Type:   layers.DHCPOptClientID,
			Length: uint8(len(hw)) + 1,
			Data:   append([]byte{0x01}, []byte(hw)...),
		},
		{
			Type:   layers.DHCPOptHostname,
			Length: uint8(len(hostname)),
			Data:   hn,
		},

		{
			Type: layers.DHCPOptEnd,
		},
	}
	dhcp4.Options = dhcp4Opts

	buff := gopacket.NewSerializeBuffer()

	err = udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		log.Println(hw, err)
		return err
	}

	err = gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	},
		eth,
		ip,
		udp,
		dhcp4)

	if err != nil {
		log.Println(hw, err)
		return err
	}

	//fmt.Println(hex.Dump(buff.Bytes()))

	return writePacket(handle, buff.Bytes())
}
func writePacket(handle *pcap.Handle, buf []byte) error {
	if err := handle.WritePacketData(buf); err != nil {
		log.Printf("Failed to send packet: %s\n", err)
		return err
	}
	return nil
}

// getMacAddr gets the MAC hardware
// address of the host machine
func getMacAddr(name string) (addr string) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				if name == i.Name {
					// Don't use random as we have a real address
					addr = i.HardwareAddr.String()
				}
			}
		}
	}
	return
}
