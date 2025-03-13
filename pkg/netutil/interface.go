package netutil

import (
	"net"
)

// Interface represents a network interface with its addresses
type Interface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// GetInterfaceAddresses returns all network interfaces and their associated IP addresses
func GetInterfaceAddresses() ([]Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []Interface

	for _, iface := range interfaces {
		// Skip interfaces that are down
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var addresses []string
		for _, addr := range addrs {
			// Convert address to CIDR notation
			if ipnet, ok := addr.(*net.IPNet); ok {
				addresses = append(addresses, ipnet.IP.String())
			}
		}

		if len(addresses) > 0 {
			result = append(result, Interface{
				Name:      iface.Name,
				Addresses: addresses,
			})
		}
	}

	return result, nil
}

// GetInterfaceByName returns IP addresses associated with a specific interface name
func GetInterfaceByName(name string) (*Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var addresses []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			addresses = append(addresses, ipnet.IP.String())
		}
	}

	return &Interface{
		Name:      iface.Name,
		Addresses: addresses,
	}, nil
}
