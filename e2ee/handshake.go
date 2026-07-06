package e2ee

import (
	"fmt"
	"strings"
)

// --- Secure Relay Transcripts (via backend tunnel) ---

// BuildSecureRelayHelloTranscript builds the hello transcript for secure relay handshake.
func BuildSecureRelayHelloTranscript(
	pairID, userID, mobileDeviceID, desktopDeviceID string,
	mobileKeyVersion, desktopKeyVersion int,
	sessionID, desktopEphemeralPublicKey, desktopNonce string,
) string {
	return strings.Join([]string{
		"paired_e2ee_relay_hello_v2",
		pairID,
		userID,
		mobileDeviceID,
		desktopDeviceID,
		fmt.Sprintf("%d", mobileKeyVersion),
		fmt.Sprintf("%d", desktopKeyVersion),
		sessionID,
		desktopEphemeralPublicKey,
		desktopNonce,
	}, "|")
}

// BuildSecureRelayAckTranscript builds the ack transcript for secure relay handshake.
func BuildSecureRelayAckTranscript(
	pairID, userID, mobileDeviceID, desktopDeviceID string,
	mobileKeyVersion, desktopKeyVersion int,
	sessionID, desktopEphemeralPublicKey, mobileEphemeralPublicKey,
	desktopNonce, mobileNonce string,
) string {
	return strings.Join([]string{
		"paired_e2ee_relay_ack_v2",
		pairID,
		userID,
		mobileDeviceID,
		desktopDeviceID,
		fmt.Sprintf("%d", mobileKeyVersion),
		fmt.Sprintf("%d", desktopKeyVersion),
		sessionID,
		desktopEphemeralPublicKey,
		mobileEphemeralPublicKey,
		desktopNonce,
		mobileNonce,
	}, "|")
}

// BuildSecureRelayForwardSecretSessionInfo builds the session info for key derivation.
func BuildSecureRelayForwardSecretSessionInfo(
	pairID, userID, mobileDeviceID, desktopDeviceID string,
	mobileKeyVersion, desktopKeyVersion int,
	sessionID, desktopEphemeralPublicKey, mobileEphemeralPublicKey,
	desktopNonce, mobileNonce string,
) string {
	return strings.Join([]string{
		"paired_e2ee_relay_fs_v2",
		pairID,
		userID,
		mobileDeviceID,
		desktopDeviceID,
		fmt.Sprintf("%d", mobileKeyVersion),
		fmt.Sprintf("%d", desktopKeyVersion),
		sessionID,
		desktopEphemeralPublicKey,
		mobileEphemeralPublicKey,
		desktopNonce,
		mobileNonce,
	}, "|")
}

// --- P2P LAN Transcripts (direct desktop-to-mobile) ---

// BuildP2PHelloTranscript builds the hello transcript for P2P LAN handshake.
func BuildP2PHelloTranscript(
	ticket, pairID, userID, mobileDeviceID, desktopDeviceID string,
	mobileKeyVersion, desktopKeyVersion int,
	sessionID, clientEphemeralPublicKey, clientNonce string,
) string {
	return strings.Join([]string{
		"hello",
		ticket,
		pairID,
		userID,
		mobileDeviceID,
		desktopDeviceID,
		fmt.Sprintf("%d", mobileKeyVersion),
		fmt.Sprintf("%d", desktopKeyVersion),
		sessionID,
		clientEphemeralPublicKey,
		clientNonce,
	}, "|")
}

// BuildP2PAckTranscript builds the ack transcript for P2P LAN handshake.
func BuildP2PAckTranscript(
	ticket, pairID, userID, mobileDeviceID, desktopDeviceID string,
	mobileKeyVersion, desktopKeyVersion int,
	sessionID, clientEphemeralPublicKey, serverEphemeralPublicKey,
	clientNonce, serverNonce string,
) string {
	return strings.Join([]string{
		"ack",
		ticket,
		pairID,
		userID,
		mobileDeviceID,
		desktopDeviceID,
		fmt.Sprintf("%d", mobileKeyVersion),
		fmt.Sprintf("%d", desktopKeyVersion),
		sessionID,
		clientEphemeralPublicKey,
		serverEphemeralPublicKey,
		clientNonce,
		serverNonce,
	}, "|")
}

// BuildP2PSessionInfo builds the session info for P2P LAN key derivation.
func BuildP2PSessionInfo(
	ticket, pairID, userID, mobileDeviceID, desktopDeviceID string,
	mobileKeyVersion, desktopKeyVersion int,
	sessionID, clientEphemeralPublicKey, serverEphemeralPublicKey,
	clientNonce, serverNonce string,
) string {
	return strings.Join([]string{
		"session",
		ticket,
		pairID,
		userID,
		mobileDeviceID,
		desktopDeviceID,
		fmt.Sprintf("%d", mobileKeyVersion),
		fmt.Sprintf("%d", desktopKeyVersion),
		sessionID,
		clientEphemeralPublicKey,
		serverEphemeralPublicKey,
		clientNonce,
		serverNonce,
	}, "|")
}
