package mochi

import (
	"log/slog"

	"github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/storage"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/mochi-mqtt/server/v2/system"

	"github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// cfgmsAuthHook implements mochi-mqtt's Hook interface for CFGMS authentication and authorization.
// Most methods are no-ops, we only implement authentication and authorization.
type cfgmsAuthHook struct {
	mqtt.HookBase // Embed base to get default implementations
	authHandler   interfaces.AuthenticationHandler
	aclHandler    interfaces.AuthorizationHandler
}

// ID returns the hook identifier.
func (h *cfgmsAuthHook) ID() string {
	return "cfgms-auth-hook"
}

// Provides indicates which hook methods this hook implements.
func (h *cfgmsAuthHook) Provides(b byte) bool {
	// We only provide OnConnectAuthenticate and OnACLCheck
	return b == mqtt.OnConnectAuthenticate || b == mqtt.OnACLCheck
}

// Init initializes the hook (required by Hook interface).
func (h *cfgmsAuthHook) Init(config any) error {
	// No initialization needed
	return nil
}

// Stop stops the hook (required by Hook interface).
func (h *cfgmsAuthHook) Stop() error {
	// No cleanup needed
	return nil
}

// SetOpts sets the logger and hook options (required by Hook interface).
func (h *cfgmsAuthHook) SetOpts(l *slog.Logger, o *mqtt.HookOptions) {
	// We don't need to store these for our use case
}

// OnConnectAuthenticate is called when a client attempts to connect.
//
// This implements the authentication hook using CFGMS AuthenticationHandler.
// Returns true to allow connection, false to reject.
func (h *cfgmsAuthHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	// If no auth handler is configured, allow all (for testing)
	if h.authHandler == nil {
		return true
	}

	// Extract client ID
	clientID := cl.ID

	// Extract username and password from CONNECT packet
	username := string(pk.Connect.Username)
	password := string(pk.Connect.Password)

	// Call CFGMS authentication handler
	return h.authHandler(clientID, username, password)
}

// OnACLCheck is called when a client attempts to publish or subscribe.
//
// This implements the authorization hook using CFGMS AuthorizationHandler.
// Returns true to allow operation, false to reject.
func (h *cfgmsAuthHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	// If no ACL handler is configured, allow all (for testing)
	if h.aclHandler == nil {
		return true
	}

	clientID := cl.ID
	operation := "subscribe"
	if write {
		operation = "publish"
	}

	// Call CFGMS authorization handler
	return h.aclHandler(clientID, topic, operation)
}

// The following methods are no-ops but required by the Hook interface

func (h *cfgmsAuthHook) OnStarted()                                             {}
func (h *cfgmsAuthHook) OnStopped()                                             {}
func (h *cfgmsAuthHook) OnSysInfoTick(*system.Info)                             {}
func (h *cfgmsAuthHook) OnConnect(cl *mqtt.Client, pk packets.Packet) error    { return nil }
func (h *cfgmsAuthHook) OnSessionEstablish(cl *mqtt.Client, pk packets.Packet) {}
func (h *cfgmsAuthHook) OnSessionEstablished(cl *mqtt.Client, pk packets.Packet) {}
func (h *cfgmsAuthHook) OnDisconnect(cl *mqtt.Client, err error, expire bool)  {}
func (h *cfgmsAuthHook) OnAuthPacket(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	return pk, nil
}
func (h *cfgmsAuthHook) OnPacketRead(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	return pk, nil
}
func (h *cfgmsAuthHook) OnPacketEncode(cl *mqtt.Client, pk packets.Packet) packets.Packet {
	return pk
}
func (h *cfgmsAuthHook) OnPacketSent(cl *mqtt.Client, pk packets.Packet, b []byte) {}
func (h *cfgmsAuthHook) OnPacketProcessed(cl *mqtt.Client, pk packets.Packet, err error) {}
func (h *cfgmsAuthHook) OnSubscribe(cl *mqtt.Client, pk packets.Packet) packets.Packet {
	return pk
}
func (h *cfgmsAuthHook) OnSubscribed(cl *mqtt.Client, pk packets.Packet, reasonCodes []byte) {}
func (h *cfgmsAuthHook) OnSelectSubscribers(subs *mqtt.Subscribers, pk packets.Packet) *mqtt.Subscribers {
	return subs
}
func (h *cfgmsAuthHook) OnUnsubscribe(cl *mqtt.Client, pk packets.Packet) packets.Packet {
	return pk
}
func (h *cfgmsAuthHook) OnUnsubscribed(cl *mqtt.Client, pk packets.Packet) {}
func (h *cfgmsAuthHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	return pk, nil
}
func (h *cfgmsAuthHook) OnPublished(cl *mqtt.Client, pk packets.Packet)                    {}
func (h *cfgmsAuthHook) OnPublishDropped(cl *mqtt.Client, pk packets.Packet)               {}
func (h *cfgmsAuthHook) OnRetainMessage(cl *mqtt.Client, pk packets.Packet, r int64)       {}
func (h *cfgmsAuthHook) OnRetainPublished(cl *mqtt.Client, pk packets.Packet)              {}
func (h *cfgmsAuthHook) OnQosPublish(cl *mqtt.Client, pk packets.Packet, sent int64, resends int) {
}
func (h *cfgmsAuthHook) OnQosComplete(cl *mqtt.Client, pk packets.Packet)         {}
func (h *cfgmsAuthHook) OnQosDropped(cl *mqtt.Client, pk packets.Packet)          {}
func (h *cfgmsAuthHook) OnPacketIDExhausted(cl *mqtt.Client, pk packets.Packet)   {}
func (h *cfgmsAuthHook) OnWill(cl *mqtt.Client, will mqtt.Will) (mqtt.Will, error) {
	return will, nil
}
func (h *cfgmsAuthHook) OnWillSent(cl *mqtt.Client, pk packets.Packet)  {}
func (h *cfgmsAuthHook) OnClientExpired(cl *mqtt.Client)                {}
func (h *cfgmsAuthHook) OnRetainedExpired(filter string)                {}
func (h *cfgmsAuthHook) StoredClients() ([]storage.Client, error)       { return nil, nil }
func (h *cfgmsAuthHook) StoredSubscriptions() ([]storage.Subscription, error) {
	return nil, nil
}
func (h *cfgmsAuthHook) StoredInflightMessages() ([]storage.Message, error) {
	return nil, nil
}
func (h *cfgmsAuthHook) StoredRetainedMessages() ([]storage.Message, error) {
	return nil, nil
}
func (h *cfgmsAuthHook) StoredSysInfo() (storage.SystemInfo, error) {
	return storage.SystemInfo{}, nil
}
