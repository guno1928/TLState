package TLState

import (
	"encoding/binary"

	"github.com/41Baloo/TLState/byteBuffer"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
)

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.1
/*
enum {
	invalid(0),
	change_cipher_spec(20),
	alert(21),
	handshake(22),
	application_data(23),
	heartbeat(24),  RFC 6520
	(255)
} ContentType;
*/
type RecordType uint8

const (
	RecordTypeInvalid      RecordType = iota
	RecordTypeChangeCipher RecordType = (0x13 + iota)
	RecordTypeAlert
	RecordTypeHandshake
	RecordTypeApplicationData
	RecordTypeHeartbeat
)

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3
/*
enum {
	hello_request_RESERVED(0),
	client_hello(1),
	server_hello(2),
	hello_verify_request_RESERVED(3),
	new_session_ticket(4),
	end_of_early_data(5),
	hello_retry_request_RESERVED(6),
	encrypted_extensions(8),
	certificate(11),
	server_key_exchange_RESERVED(12),
	certificate_request(13),
	server_hello_done_RESERVED(14),
	certificate_verify(15),
	client_key_exchange_RESERVED(16),
	finished(20),
	certificate_url_RESERVED(21),
	certificate_status_RESERVED(22),
	supplemental_data_RESERVED(23),
	key_update(24),
	message_hash(254),
	(255)
} HandshakeType;
*/
type HandshakeType uint8

const (
	HandshakeTypeRequest_RESERVED HandshakeType = iota
	HandshakeTypeClientHello
	HandshakeTypeServerHello
	HandshakeTypeVerifyRequest_RESERVED
	HandshakeTypeNewSessionTicket
	HandshakeTypeEndOfEarlyData
	HandshakeTypeRetryRequest_RESERVED
	HandshakeTypeEncryptedExtensions        HandshakeType = 8
	HandshakeTypeCertificate                HandshakeType = 11
	HandshakeTypeServerKeyExchange_RESERVED HandshakeType = iota + 3 // 12
	HandshakeTypeCertificateRequest
	HandshakeTypeServerHelloDone_RESERVED
	HandshakeTypeCertificateVerify
	HandshakeTypeClientKeyExchange_RESERVED
	HandshakeTypeFinished                HandshakeType = 20
	HandshakeTypeCertificateUrl_RESERVED HandshakeType = iota + 6 // 21
	HandshakeTypeCertificateStatus_RESERVED
	HandshakeTypeSupplementalData_RESERVED
	HandshakeTypeKeyUpdate
	HandshakeTypeMessageHash = 254
)

// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
/*
+------------------------------+-------------+
| Description                  | Value       |
+------------------------------+-------------+
| TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
|                              |             |
| TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
|                              |             |
| TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
|                              |             |
| TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
|                              |             |
| TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
+------------------------------+-------------+
*/
type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256 CipherSuite = (0x1301 + iota)
	TLS_AES_256_GCM_SHA384             // not implemented
	TLS_CHACHA20_POLY1305_SHA256
	TLS_AES_128_CCM_SHA256   // not implemented
	TLS_AES_128_CCM_8_SHA256 // not implemented
)

func (c CipherSuite) KeyLen() int {
	switch c {
	case TLS_AES_128_GCM_SHA256:
		return 16
	case TLS_AES_256_GCM_SHA384:
		return 32
	case TLS_CHACHA20_POLY1305_SHA256:
		return chacha20poly1305.KeySize
	default:
		panic("unsupported cipher suite for key length")
	}
}

func (c CipherSuite) ToBytes() []byte {
	return []byte{byte(c >> 8), byte(c & 0xFF)}
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
/*
enum {
	RSASSA-PKCS1-v1_5 algorithms
	rsa_pkcs1_sha256(0x0401),
	rsa_pkcs1_sha384(0x0501),
	rsa_pkcs1_sha512(0x0601),

	ECDSA algorithms
	ecdsa_secp256r1_sha256(0x0403),
	ecdsa_secp384r1_sha384(0x0503),
	ecdsa_secp521r1_sha512(0x0603),

	RSASSA-PSS algorithms with public key OID rsaEncryption
	rsa_pss_rsae_sha256(0x0804),
	rsa_pss_rsae_sha384(0x0805),
	rsa_pss_rsae_sha512(0x0806),

	EdDSA algorithms
	ed25519(0x0807),
	ed448(0x0808),

	RSASSA-PSS algorithms with public key OID RSASSA-PSS
	rsa_pss_pss_sha256(0x0809),
	rsa_pss_pss_sha384(0x080a),
	rsa_pss_pss_sha512(0x080b),

	Legacy algorithms
	rsa_pkcs1_sha1(0x0201),
	ecdsa_sha1(0x0203),

	Reserved Code Points
	private_use(0xFE00..0xFFFF),
	(0xFFFF)
} SignatureScheme;
*/
type SignatureScheme uint16

const (
	RSA_PSS_RSAE_SHA256 SignatureScheme = 0x0804
)

func (s SignatureScheme) ToBytes() []byte {
	return []byte{byte(s >> 8), byte(s & 0xFF)}
}

func (s SignatureScheme) ToBytesConst() []byte {
	switch s {
	case RSA_PSS_RSAE_SHA256:
		return []byte{0x08, 0x04}
	default:
		panic("not implemented")
	}
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
/*
enum {
	server_name(0),                             RFC 6066
	max_fragment_length(1),                     RFC 6066
	status_request(5),                          RFC 6066
	supported_groups(10),                       RFC 8422, 7919
	signature_algorithms(13),                   RFC 8446
	use_srtp(14),                               RFC 5764
	heartbeat(15),                              RFC 6520
	application_layer_protocol_negotiation(16), RFC 7301
	signed_certificate_timestamp(18),           RFC 6962
	client_certificate_type(19),                RFC 7250
	server_certificate_type(20),                RFC 7250
	padding(21),                                RFC 7685
	pre_shared_key(41),                         RFC 8446
	early_data(42),                             RFC 8446
	supported_versions(43),                     RFC 8446
	cookie(44),                                 RFC 8446
	psk_key_exchange_modes(45),                 RFC 8446
	certificate_authorities(47),                RFC 8446
	oid_filters(48),                            RFC 8446
	post_handshake_auth(49),                    RFC 8446
	signature_algorithms_cert(50),              RFC 8446
	key_share(51),                              RFC 8446
	(65535)
} ExtensionType;
*/
type Extension uint8

const (
	ExtensionSupportedVersions Extension = 43
	ExtensionKeyShare          Extension = 51
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
/*
enum {
	Elliptic Curve Groups (ECDHE)
	secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
	x25519(0x001D), x448(0x001E),

	Finite Field Groups (DHE)
	ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
	ffdhe6144(0x0103), ffdhe8192(0x0104),

	Reserved Code Points
	ffdhe_private_use(0x01FC..0x01FF),
	ecdhe_private_use(0xFE00..0xFEFF),
	(0xFFFF)
} NamedGroup;
*/
type NamedGroup uint16

const (
	NamedGroupX25519 NamedGroup = 0x001D
)

const (
	ProtocolVersion = 0x0303 // Backwards compatibility
	TLS13Version    = 0x0304
)

type HandshakeMessage []byte
type RecordMessage []byte

// will use the contents of "inOut" buffer and replace them with a handshakeMessage
func marshallHandshake(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) ResponseState {

	bodyLen := inOut.Len()

	hdr := make([]byte, 4) // Escapes to heap
	hdr[0] = byte(msgType)
	hdr[1] = byte(bodyLen >> 16)
	hdr[2] = byte(bodyLen >> 8)
	hdr[3] = byte(bodyLen)
	inOut.B = append(hdr, inOut.B...)

	return Responded
}

func marshallAdditionalData(length int) []byte {
	return []byte{ // Escapes to heap
		byte(RecordTypeApplicationData),
		byte(ProtocolVersion >> 8),
		byte(ProtocolVersion & 0xFF),
		byte(length >> 8),
		byte(length & 0xFF),
	}
}

func BuildHandshakeMessage(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) ResponseState {
	marshallHandshake(msgType, inOut)

	return BuildRecordMessage(RecordTypeHandshake, inOut)
}

// Wrap payload in full TLS record (type + version + 2-byte length).
func BuildRecordMessage(recType RecordType, inOut *byteBuffer.ByteBuffer) ResponseState {
	header := make([]byte, 5) // Escapes to heap
	header[0] = byte(recType)
	header[1] = byte(ProtocolVersion >> 8)
	header[2] = byte(ProtocolVersion & 0xFF)
	binary.BigEndian.PutUint16(header[3:], uint16(inOut.Len()))

	inOut.B = append(header, inOut.B...)

	return Responded
}

func (t *TLState) BuildEncryptedHandshakeMessage(msgType HandshakeType, inOut *byteBuffer.ByteBuffer) ResponseState {

	marshallHandshake(msgType, inOut)

	// record for transcript hash (per RFC8446 §4.1.3)
	t.handshakeMessages.Write(inOut.B)

	inOut.WriteByte(byte(RecordTypeHandshake))

	// Create additional data (record header)
	messageLength := inOut.Len()
	recordLength := messageLength + 16 // Add 16 for auth tag

	inOut.Write(t.serverHandshakeIV)
	nonce := inOut.B[messageLength:]

	inOut.Write(marshallAdditionalData(recordLength))
	additionalData := inOut.B[messageLength+12:]

	nonceCount := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceCount, t.serverRecordCount)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= nonceCount[i]
	}
	t.serverRecordCount++

	aead, err := t.createAEAD(t.serverHandshakeKey)
	if err != nil { // TODO: get rid of silent failure
		log.Error().Err(err).Msg("Failed to create AEAD cipher")
		return None
	}

	ciphertext := aead.Seal(nil, nonce, inOut.B[:messageLength], additionalData)

	// No longer need the input, time to replace it with the output.
	inOut.Reset()
	inOut.Write(additionalData)
	inOut.Write(ciphertext)

	return Responded
}
