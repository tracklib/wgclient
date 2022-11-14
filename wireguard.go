package wgclient

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/rs/zerolog/log"
)

//go:embed client_config_template.conf
var clientConfigTemplateData []byte

var clientConfigTemplate = template.Must(template.New("conf").Parse(string(clientConfigTemplateData)))

func RenderClientConfig(renderContext TemplateContext) ([]byte, error) {
	var b bytes.Buffer
	err := clientConfigTemplate.Execute(&b, renderContext)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// TemplateContext is a template for rending a single end user client config file.
type TemplateContext struct {
	PrivateKey    string
	PeerPublicKey string
	PeerEndpoint  string
	NetPrefix     string
	NetSuffix     string
	DNS           string
	AllowedIPS    string
}

type Config struct {
	Users           Users
	AllowedIPs      []string
	DNSNames        []string
	DNS             []string
	ServerPublicKey string
	Interfaces      Interfaces
}

func (c *Config) UpdateAllowedIPs(ctx context.Context, nameserver string) error {
	r := net.DefaultResolver
	if nameserver != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 10,
				}
				return d.DialContext(ctx, network, nameserver)
			},
		}
	}
	var res []string
	for _, n := range c.DNSNames {
		ips, err := r.LookupIP(ctx, "ip4", n)
		if err != nil {
			log.Error().Str("dns_name", n).Err(err).Msg("")
			return err
		}
		if len(ips) == 0 {
			log.Error().Str("dns_name", n).Msg("no DNS resolver response for dns name")
			return errors.New("no DNS resolver response for dns name")
		}
		for _, ip := range ips {
			res = append(res, fmt.Sprintf("%s/32", ip))
		}
	}
	res = append(res, c.AllowedIPs...)
	sort.Strings(res)
	c.AllowedIPs = compact(res)
	return nil
}

func (c *Config) UpdateAllowedIPsWithDefaultResolver(ctx context.Context) error {
	var res []string
	for _, n := range c.DNSNames {

		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", n)
		if err != nil {
			log.Error().Str("dns_name", n).Err(err).Msg("")
			return err
		}
		if len(ips) == 0 {
			log.Error().Str("dns_name", n).Msg("no DNS resolver response for dns name")
			return errors.New("no DNS resolver response for dns name")
		}
		for _, ip := range ips {
			res = append(res, fmt.Sprintf("%s/32", ip))
		}
	}
	res = append(res, c.AllowedIPs...)
	sort.Strings(res)
	c.AllowedIPs = compact(res)
	return nil
}

func (c Config) AllClientConfigs() ClientConfigs {
	var cc ClientConfigs
	for i := range c.Interfaces {
		cc = append(cc,
			ClientConfig{
				IF:       i,
				NoDNS:    false,
				RouteDNS: false,
			},
			ClientConfig{
				IF:       i,
				NoDNS:    true,
				RouteDNS: false,
			},
			ClientConfig{
				IF:       i,
				NoDNS:    false,
				RouteDNS: true,
			},
		)
	}
	return cc
}

// Interface .
type Interface struct {
	Endpoint string
	Prefix   string
}

// ClientConfig .
type ClientConfig struct {
	IF       int  `json:"if"`        // interface 0=wg0 1=wg1...
	NoDNS    bool `json:"no_dns"`    // comment out the DNS =  line
	RouteDNS bool `json:"route_dns"` // Append the DNS servers to AllowedIPs line
}

func (w User) Filename(cc ClientConfig) string {
	var ib strings.Builder
	ib.WriteString("_")
	ib.WriteString(fmt.Sprint(cc.IF))
	if cc.NoDNS {
		ib.WriteString("n")
	}
	if !cc.NoDNS && cc.RouteDNS {
		ib.WriteString("r")
	}

	name := w.Name
	infix := ib.String()
	if len(name)+len(infix) > 15 {
		end := 15 - len(infix)
		if end < 1 {
			end = 1
		}
		name = name[:end]
	}
	s := name + infix
	if len(s) > 15 {
		s = s[:15]
	}
	s = strings.TrimRight(s, "_")
	if !TunnelNameIsValid(s) {
		log.Error().Msgf("not a valid tunnel name: %s", s)
		return "wireguard.conf"
	}
	return s + ".conf"
}

type ClientConfigs []ClientConfig

type Interfaces map[int]Interface

// User .
type User struct {
	Name          string        `json:"name"`
	Priv          string        `json:"priv"`
	Pub           string        `json:"pub"`
	ClientConfigs ClientConfigs `json:"configs"`
	Email         string        `json:"email"`
	Tags          []string      `json:"tags"`
}

type Users map[string]User

func (u Users) FindUserByName(name string) (string, User, error) {
	for k, v := range u {
		if name == v.Name {
			return k, v, nil
		}
	}
	return "", User{}, fmt.Errorf("could not find user with name %s in config.json", name)
}

func (u Users) Match(s ...string) Users {
	res := make(Users)
	contains := func(v string) bool {
		for _, s := range s {
			if strings.Contains(v, s) {
				return true
			}
		}
		return false
	}
loop:
	for k, uc := range u {
		if contains(uc.Name) {
			res[k] = uc
			continue loop
		}
		if contains(uc.Email) {
			res[k] = uc
			continue loop
		}
	}
	return res
}

func (u Users) FilterTags(s ...string) Users {
	res := make(Users)
loop:
	for k, uc := range u {
		for _, got := range uc.Tags {
			for _, want := range s {
				if got == want {
					res[k] = uc
					continue loop
				}
			}
		}
	}
	return res
}

func ReadConfig(data []byte) (Config, error) {
	var v Config
	err := json.Unmarshal(data, &v)
	if err != nil {
		return Config{}, err
	}
	for _, u := range v.Users {
		if !TunnelNameIsValid(u.Name) {
			if len(u.Name) > 15 {
				return Config{}, fmt.Errorf("tunnel config name '%v' can not be longer than 32 characters", u.Name)
			}
			return Config{}, fmt.Errorf("tunnel config name '%v' is not a valid windows tunnel name", u.Name)
		}
	}
	return v, nil
}

var reservedNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

const (
	serviceNameForbidden = "$"
	netshellDllForbidden = "\\/:*?\"<>|\t"
	specialChars         = "/\\<>:\"|?*\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00"
)

var allowedNameFormat *regexp.Regexp

func init() {
	allowedNameFormat = regexp.MustCompile("^[a-zA-Z0-9_=+.-]{1,32}$")
}

func isReserved(name string) bool {
	if len(name) == 0 {
		return false
	}
	for _, reserved := range reservedNames {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

func hasSpecialChars(name string) bool {
	return strings.ContainsAny(name, specialChars) || strings.ContainsAny(name, netshellDllForbidden) || strings.ContainsAny(name, serviceNameForbidden)
}

// TunnelNameIsValid is copied from wireguard windows client because windows put a series of restrictions on tunnel names.
func TunnelNameIsValid(name string) bool {
	// Aside from our own restrictions, let's impose the Windows restrictions first
	if isReserved(name) || hasSpecialChars(name) {
		return false
	}
	return allowedNameFormat.MatchString(name)
}

// compact replaces consecutive runs of equal elements with a single copy.
// This is like the uniq command found on Unix.
// Compact modifies the contents of the slice s; it does not create a new slice.
func compact[S ~[]E, E comparable](s S) S {
	if len(s) == 0 {
		return s
	}
	i := 1
	last := s[0]
	for _, v := range s[1:] {
		if v != last {
			s[i] = v
			i++
			last = v
		}
	}
	return s[:i]
}
