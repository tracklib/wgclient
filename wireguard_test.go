package wgclient

import (
	"context"
	"testing"

	_ "embed"

	"github.com/stretchr/testify/assert"
)

//go:embed testdata/config.json
var testConfig []byte

func TestReadConfig(t *testing.T) {
	conf, err := ReadConfig(testConfig)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("count", func(t *testing.T) {
		count := len(conf.Users)
		if count != 2 {
			t.Errorf("expected 2 users, got: %v", count)
		}
	})

	t.Run("match", func(t *testing.T) {
		users := conf.Users.Match("one", "two")
		count := len(users)
		if count != 2 {
			t.Errorf("expected 2 users, got: %v", count)
		}
	})

	t.Run("match", func(t *testing.T) {
		users := conf.Users.Match("one")
		count := len(users)
		if count != 1 {
			t.Errorf("expected 1 users, got: %v", count)
		}
	})

	t.Run("match", func(t *testing.T) {
		users := conf.Users.Match("none")
		count := len(users)
		if count != 0 {
			t.Errorf("expected 0 users, got: %v", count)
		}
	})

	t.Run("filter tags", func(t *testing.T) {
		users := conf.Users.FilterTags("nothing", "dev")
		count := len(users)
		t.Log(users)
		if count != 1 || count == len(conf.Users) {
			t.Errorf("expected 1 dev users but not all, got: %v", count)
		}
	})

	t.Run("find", func(t *testing.T) {
		suffix, user, err := conf.Users.FindUserByName("two")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "2", suffix)
		assert.Equal(t, "two", user.Name)
		assert.Equal(t, "two@example.com", user.Email)
		assert.Len(t, user.ClientConfigs, 4)
	})

}

func TestRenderConfig(t *testing.T) {
	c := TemplateContext{
		PrivateKey:    "priv-key",
		PeerPublicKey: "peer-pub-key",
		PeerEndpoint:  "peer-endpoint",
		NetPrefix:     "99.99.99.",
		NetSuffix:     "100",
		DNS:           "1,2",
		AllowedIPS:    "1.1.1.1/32",
	}

	t.Run("render1", func(t *testing.T) {
		data, err := RenderClientConfig(c)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, `[Interface]
PrivateKey = priv-key
Address = 99.99.99.100/32
DNS = 1,2

[Peer]
PublicKey = peer-pub-key
Endpoint = peer-endpoint
PersistentKeepalive = 25
AllowedIPs = 1.1.1.1/32
`, string(data))
	})

	t.Run("render2", func(t *testing.T) {
		c := c
		c.DNS = ""
		data, err := RenderClientConfig(c)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, `[Interface]
PrivateKey = priv-key
Address = 99.99.99.100/32

[Peer]
PublicKey = peer-pub-key
Endpoint = peer-endpoint
PersistentKeepalive = 25
AllowedIPs = 1.1.1.1/32
`, string(data))
	})
}

func TestUser(t *testing.T) {
	user := User{
		Name: "name",
		Priv: "priv",
		Pub:  "pub",
	}

	t.Run("default", func(t *testing.T) {
		assert.Equal(t, "name_0.conf", user.Filename(ClientConfig{}))
	})

	t.Run("if99", func(t *testing.T) {
		assert.Equal(t, "name_99.conf", user.Filename(ClientConfig{
			IF: 99,
		}))
	})

	t.Run("no-dns", func(t *testing.T) {
		assert.Equal(t, "name_0n.conf", user.Filename(ClientConfig{
			NoDNS: true,
		}))
	})

	t.Run("route-dns", func(t *testing.T) {
		assert.Equal(t, "name_0r.conf", user.Filename(ClientConfig{
			RouteDNS: true,
		}))
	})

	t.Run("no-dns_route-dns", func(t *testing.T) {
		assert.Equal(t, "name_0n.conf", user.Filename(ClientConfig{
			RouteDNS: true,
			NoDNS:    true,
		}))
	})

	t.Run("shortened name", func(t *testing.T) {
		user := user
		user.Name = "1234567890123456789012345678901234567890"
		assert.Equal(t, "123456789012_0n.conf", user.Filename(ClientConfig{
			RouteDNS: true,
			NoDNS:    true,
		}))
	})

	t.Run("invalid name", func(t *testing.T) {
		user := user
		user.Name = "C:\\"
		assert.Equal(t, "wireguard.conf", user.Filename(ClientConfig{
			RouteDNS: true,
			NoDNS:    true,
		}))
	})
}

func TestUpdateAllowedIPs(t *testing.T) {
	t.Run("default resovler", func(t *testing.T) {
		conf, err := ReadConfig(testConfig)
		if err != nil {
			t.Error(err)
		}
		assert.NoError(t, conf.UpdateAllowedIPs(context.Background(), ""))
		assert.Greater(t, len(conf.AllowedIPs), 2)

	})

	t.Run("specified resolver", func(t *testing.T) {
		conf, err := ReadConfig(testConfig)
		if err != nil {
			t.Error(err)
		}
		assert.Len(t, conf.AllowedIPs, 2)
		assert.NoError(t, conf.UpdateAllowedIPs(context.Background(), "1.1.1.1:53"))
		assert.Greater(t, len(conf.AllowedIPs), 2)
	})

}
