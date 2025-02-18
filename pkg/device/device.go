package device

import (
	"regexp"

	"github.com/vishvananda/netlink"
)

func FindMatchedDevices(dev string) ([]netlink.Link, error) {
	re, err := regexp.Compile(dev)
	if err != nil {
		return nil, err
	}
	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	matchedList := make([]netlink.Link, 0)
	for _, l := range linkList {
		if re.MatchString(l.Attrs().Name) {
			matchedList = append(matchedList, l)
		}
	}
	return matchedList, nil
}
