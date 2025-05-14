package TLState

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/41Baloo/TLState/byteBuffer"
	"github.com/rs/zerolog/log"
)

func (t *TLState) processHandshake(in *byteBuffer.ByteBuffer) ResponseState {
	for {
		in.Reset()
		if t.handshakeState == HandshakeStateDone {
			return None
		}

		buffered := t.incoming.Buffered()
		if buffered < 5 {
			break
		}

		head, tail := t.incoming.Peek(5)
		recType := RecordType(head[0])

		b0 := GetHeadTail(2, head[1:], tail)
		b1 := GetHeadTail(3, head[1:], tail)

		length := int(binary.BigEndian.Uint16([]byte{b0, b1}))

		if buffered < 5+length {
			break
		}

		rawHeader := make([]byte, 5) // Escapes to heap
		t.incoming.Read(rawHeader)

		head, tail = t.incoming.Peek(length)
		t.incoming.Discard(length)
		in.Write(head)
		in.Write(tail)

		switch recType {
		case RecordTypeChangeCipher:
			continue

		case RecordTypeHandshake:
			resp, _ := t.processHandshakeMessage(in)
			return resp

		case RecordTypeApplicationData:
			if t.handshakeState >= HandshakeStateServerHelloDone {
				t.processEncryptedHandshake(in, rawHeader)
				return None
			} else {
				log.Warn().Int("State", int(t.handshakeState)).Msg("Received unexpected application data during early handshake")
			}

		default:
			log.Warn().Uint8("record_type", uint8(recType)).Msg("Unknown record type")
		}
	}

	return None
}

func (t *TLState) processHandshakeMessage(data *byteBuffer.ByteBuffer) (ResponseState, error) {
	// Handshake headers are at least 4 bytes
	dataLen := data.Len()
	if dataLen < 4 {
		return None, nil
	}

	msgType := data.B[0]
	length := uint32(data.B[1])<<16 | uint32(data.B[2])<<8 | uint32(data.B[3])

	if dataLen < int(4+length) {
		return None, nil
	}

	switch HandshakeType(msgType) {
	case HandshakeTypeClientHello:
		t.handshakeMessages.Write(data.B[:4+length])
		data.B = data.B[4 : 4+length]

		return t.processClientHello(data)
	default:
		log.Warn().Uint8("handshake_type", msgType).Msg("Unexpected handshake message type")
		return None, nil
	}
}

func (t *TLState) processClientHello(data *byteBuffer.ByteBuffer) (ResponseState, error) {

	dataLen := data.Len()
	if dataLen < 34 {
		return None, nil
	}

	// Extract client version (will be ignored in TLS 1.3)
	// clientVersion := binary.BigEndian.Uint16(data.B[0:2])

	copy(t.clientRandom, data.B[2:34])

	// Extract session ID
	sessionIDLength := int(data.B[34])
	if dataLen < 35+sessionIDLength {
		return None, nil
	}
	t.sessionID = append(t.sessionID, data.B[35:35+sessionIDLength]...)

	offset := 35 + sessionIDLength
	if dataLen < offset+2 {
		return None, nil
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(data.B[offset : offset+2]))
	offset += 2
	if dataLen < offset+cipherSuitesLength {
		return None, nil
	}

ciphers:
	for _, sCipher := range t.Config.Ciphers {
		for i := 0; i < cipherSuitesLength && t.cipher == 0; i += 2 {
			if offset+i+1 >= dataLen {
				continue
			}
			suite := CipherSuite(binary.BigEndian.Uint16(data.B[offset+i : offset+i+2]))
			if suite == sCipher {
				t.cipher = suite
				break ciphers
			}
		}
	}

	if t.cipher == 0 {
		return None, ErrCiphersNotSupported
	}

	// Move past cipher suites and compression methods to extensions
	offset += cipherSuitesLength
	if dataLen < offset+1 {
		return None, nil
	}
	compressMethodsLength := int(data.B[offset])
	offset += 1 + compressMethodsLength

	if dataLen < offset+2 {
		return None, nil
	}
	extensionsLength := int(binary.BigEndian.Uint16(data.B[offset : offset+2]))
	offset += 2
	if dataLen < offset+extensionsLength {
		return None, nil
	}

	extensionsEnd := offset + extensionsLength
	supportsTLS13 := false
	hasKeyShare := false

	for offset < extensionsEnd {
		if offset+4 > dataLen {
			break
		}
		extType := Extension(binary.BigEndian.Uint16(data.B[offset : offset+2]))
		extLen := int(binary.BigEndian.Uint16(data.B[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > dataLen {
			break
		}

		if extType == ExtensionKeyShare {
			if extLen < 2 {
				offset += extLen
				continue
			}

			keyShareDataLen := int(binary.BigEndian.Uint16(data.B[offset : offset+2]))
			offset += 2
			keyShareEnd := offset + keyShareDataLen

			for offset < keyShareEnd {
				if offset+4 > dataLen {
					break
				}
				group := NamedGroup(binary.BigEndian.Uint16(data.B[offset : offset+2]))
				keyLen := int(binary.BigEndian.Uint16(data.B[offset+2 : offset+4]))
				offset += 4

				if offset+keyLen > dataLen {
					break
				}

				if group == NamedGroupX25519 {
					t.peerPublicKey = append(t.peerPublicKey, data.B[offset:offset+keyLen]...)
					hasKeyShare = true
					break
				}

				offset += keyLen
			}

			// Instantly skip to next extension
			offset = extensionsEnd - extLen + keyShareDataLen
		} else if extType == ExtensionSupportedVersions {
			// Check for TLS 1.3 support
			if extLen >= 2 {
				versionsLen := int(data.B[offset])
				if versionsLen+1 <= extLen {
					for i := 0; i < versionsLen; i += 2 {
						if offset+1+i+1 < dataLen {
							version := binary.BigEndian.Uint16(data.B[offset+1+i : offset+1+i+2])

							if version == TLS13Version {
								supportsTLS13 = true
								break
							}
						}
					}
				}
			}
			offset += extLen
		} else {
			offset += extLen
		}
	}

	if !supportsTLS13 {
		log.Warn().Msg("Client does not support TLS 1.3")
		return None, ErrTLS13NotSupported
	}

	if !hasKeyShare {
		log.Warn().Msg("No valid key share found")
		return None, ErrNoValidKeyShare
	}

	t.handshakeState = HandshakeStateClientHelloDone

	// We no longer need any input from hereon out. Simply re-use this buffer for our output
	data.Reset()
	return t.generateServerResponse(data)
}

// We take in an out byteBuffer that we write our response to, to avoid heap allocations
func (t *TLState) generateServerResponse(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	resp, err := t.generateServerHello(out)
	if err != nil {
		return resp, err
	}

	t.handshakeMessages.Write(out.B[5:]) // Skip record header

	err = t.calculateHandshakeKeys()
	if err != nil {
		return None, nil
	}

	t.generateChangeCipherSpec(out)
	t.generateEncryptedExtensionsRecord(out)
	t.generateCertificateRecord(out)
	resp, err = t.generateCertificateVerifyRecord(out)
	if err != nil {
		return resp, err
	}
	t.generateFinishedRecord(out)

	t.handshakeState = HandshakeStateWaitClientFinished

	return Responded, nil
}

// Write serverHello info buffer
func (t *TLState) generateServerHello(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	serverRandom := make([]byte, 32) // Escapes to heap
	_, err := io.ReadFull(rand.Reader, serverRandom)
	if err != nil {
		return None, err
	}

	out.Write([]byte{
		0x03, 0x03, // Legacy version (TLS 1.2)
	})
	out.Write(serverRandom)

	out.WriteByte(byte(len(t.sessionID)))
	out.Write(t.sessionID)

	// Our negotiated cipher
	out.Write(t.cipher.ToBytes())
	out.WriteByte(0x00)

	t.generateServerHelloExtensions(out)

	BuildHandshakeMessage(HandshakeTypeServerHello, out)

	return Responded, nil
}

// Will write ServerHelloExtensions to out
func (t *TLState) generateServerHelloExtensions(out *byteBuffer.ByteBuffer) ResponseState {

	// To avoid an extra buffer here, we can instantly figure out what the final length will be
	// We instantly write it and then append the actual extenions.
	// supported_versions => 6
	// key_share => 8
	// t.publicKey => len(t.publicKey)
	pubKeyLen := len(t.publicKey)
	var EXTENSION_LENGTH = 6 + 8 + pubKeyLen
	out.Write([]byte{
		byte(EXTENSION_LENGTH >> 8), byte(EXTENSION_LENGTH),
	})

	// supported_versions extension
	out.Write([]byte{
		0x00, 0x2B, // supported_versions, not using constant here for performance
		0x00, 0x02, // Length
		0x03, 0x04, // TLS 1.3
	})

	// key_share extension
	keyShareLen := 2 + 2 + pubKeyLen
	out.Write([]byte{
		0x00, 0x33, // Extension type, not using constant, due to performance
		byte(keyShareLen >> 8), byte(keyShareLen), // Length
		0x00, 0x1D, // x25519, again not using constant here, for performance
		byte(pubKeyLen >> 8),
		byte(pubKeyLen),
	})

	out.Write(t.publicKey)

	return Responded
}

func (t *TLState) generateChangeCipherSpec(out *byteBuffer.ByteBuffer) ResponseState {
	// Change cipher spec for compatibility with middleboxes

	buff := byteBuffer.Get()
	buff.Write([]byte{0x01})

	resp := BuildRecordMessage(RecordTypeChangeCipher, buff)
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp
}

func (t *TLState) generateEncryptedExtensionsRecord(out *byteBuffer.ByteBuffer) ResponseState {

	buff := byteBuffer.Get()
	buff.Write([]byte{
		0x00, 0x00, // We don't support any extensions
	})

	resp := t.BuildEncryptedHandshakeMessage(HandshakeTypeEncryptedExtensions, buff)
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp
}

func (t *TLState) generateCertificateRecord(out *byteBuffer.ByteBuffer) ResponseState {

	buff := byteBuffer.Get()

	// CertificateRecord doesn't change from connection to connection (i think), so we just precalculate it in our config
	buff.Write(t.Config.CertificateRecord)

	resp := t.BuildEncryptedHandshakeMessage(HandshakeTypeCertificate, buff)
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp
}

func (t *TLState) generateCertificateVerifyRecord(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	outLength := out.Len()

	transcriptHash := sha256.Sum256(t.handshakeMessages.Bytes())

	// Build the context string as per RFC8446
	context := []byte("TLS 1.3, server CertificateVerify")
	contextLen := len(context)

	out.B = EnsureLen(out.B, outLength+64+len(context)+1+len(transcriptHash))
	buf := out.B[outLength:]

	// 64 0x20 bytes (space)
	for i := 0; i < 64; i++ {
		buf[i] = 0x20
	}
	copy(buf[64:], context)
	buf[64+contextLen] = 0x00
	copy(buf[64+contextLen+1:], transcriptHash[:])

	toSign := sha256.Sum256(buf)

	// We no longer need buf at this point, simply reset the length to what it was before to continue using the buffer
	out.B = out.B[:outLength]
	out.Write(toSign[:])

	signature, err := rsa.SignPSS(
		rand.Reader,
		t.Config.ParsedKey,
		crypto.SHA256,
		out.B[outLength:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
	)
	if err != nil {
		return None, err
	}
	out.B = out.B[:outLength]

	out.B = EnsureLen(out.B, outLength+2+2+len(signature))
	signatureBytes := out.B[outLength:]

	signatureScheme := RSA_PSS_RSAE_SHA256.ToBytesConst()

	copy(signatureBytes[0:2], signatureScheme)

	binary.BigEndian.PutUint16(signatureBytes[2:4], uint16(len(signature)))

	copy(signatureBytes[4:], signature)

	buff := byteBuffer.Get()
	buff.Write(signatureBytes)

	out.B = out.B[:outLength]

	resp := t.BuildEncryptedHandshakeMessage(HandshakeTypeCertificateVerify, buff)
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)

	return resp, nil
}

func (t *TLState) generateFinishedRecord(out *byteBuffer.ByteBuffer) (ResponseState, error) {

	buff := byteBuffer.Get()
	resp, err := t.calculateVerifyData(buff, t.serverHandshakeTrafficSecret)
	if err != nil {
		byteBuffer.Put(buff)
		return resp, err
	}

	resp = t.BuildEncryptedHandshakeMessage(HandshakeTypeFinished, buff)
	if resp == Responded {
		out.Write(buff.B)
	}

	byteBuffer.Put(buff)
	return resp, nil
}

func (t *TLState) calculateVerifyData(out *byteBuffer.ByteBuffer, secret []byte) (ResponseState, error) {
	resp, err := hkdfExpandLabel(out, secret, "finished", []byte{}, 32)
	if err != nil {
		return resp, err
	}

	outLength := out.Len()

	transcriptHash := sha256.Sum256(t.handshakeMessages.Bytes()) // Moved to heap
	out.Write(transcriptHash[:])

	h := hmac.New(sha256.New, out.B[:outLength])
	h.Write(out.B[outLength:])

	out.Reset()
	out.Write(h.Sum(nil))

	return Responded, nil
}

func (t *TLState) processEncryptedHandshake(in *byteBuffer.ByteBuffer, header []byte) error {

	inLength := in.Len()
	in.Write(t.clientHandshakeIV)
	nonce := in.B[inLength:]

	in.Write(header)
	additionalData := in.B[inLength+12:]

	nonceCount := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceCount, t.clientRecordCount)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= nonceCount[i]
	}
	t.clientRecordCount++

	aead, err := t.createAEAD(t.clientHandshakeKey)
	if err != nil {
		return err
	}

	plaintext, err := aead.Open(nil, nonce, in.B[:inLength], additionalData)
	if err != nil {
		return err
	}

	if len(plaintext) == 0 {
		log.Warn().Msg("Empty plaintext after decryption")
		return nil
	}

	contentType := RecordType(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-1]

	if contentType == RecordTypeHandshake && len(plaintext) >= 4 && plaintext[0] == byte(HandshakeTypeFinished) {
		t.processClientFinished(plaintext)
	}

	log.Warn().
		Uint8("content_type", uint8(contentType)).
		Uint8("first_byte", plaintext[0]).
		Msg("Not a Finished message")

	return nil
}

func (t *TLState) processClientFinished(data []byte) error {

	if len(data) < 4 {
		return nil
	}

	msgType := HandshakeType(data[0])
	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	if msgType != HandshakeTypeFinished {
		log.Warn().
			Uint8("msg_type", uint8(msgType)).
			Msg("Expected Finished message, got something else")
		return nil
	}

	if len(data) < int(4+length) {
		return nil
	}

	verifyData := data[4 : 4+length]

	buff := byteBuffer.Get()

	_, err := t.calculateVerifyData(buff, t.clientHandshakeTrafficSecret)
	if err != nil {
		byteBuffer.Put(buff)
		return err
	}

	if !hmac.Equal(verifyData, buff.B) {
		log.Warn().
			Hex("received", verifyData).
			Hex("expected", buff.B).
			Msg("Client Finished verify data mismatch")

		byteBuffer.Put(buff)
		return ErrClientFinishVerifyMissmatch
	}
	byteBuffer.Put(buff)

	// RFC 8446 7.1 first append, then calculate
	t.calculateApplicationKeys()

	t.handshakeMessages.Write(data)

	return nil
}

func (t *TLState) calculateHandshakeKeys() error {

	sharedSecret, err := curve25519.X25519(t.privateKey, t.peerPublicKey)
	if err != nil {
		return err
	}

	buff := byteBuffer.Get()
	defer byteBuffer.Put(buff)
	buff.B = EnsureLen(buff.B, 32)
	ZeroSlice(buff.B)

	hkdfExtract(buff, buff.B)
	earlySecret := make([]byte, 32) // Escapes to heap
	copy(earlySecret, buff.B)

	buff.Reset()

	emptyHash := sha256.Sum256(nil)

	//derivedSecret
	_, err = hkdfExpandLabel(buff, earlySecret, "derived", emptyHash[:], 32)
	if err != nil {
		return err
	}
	hkdfExtract(buff, sharedSecret)
	t.handshakeSecret = append(t.handshakeSecret, buff.B...)
	buff.Reset()

	transcriptHash := sha256.Sum256(t.handshakeMessages.Bytes())

	_, err = hkdfExpandLabel(
		buff,
		t.handshakeSecret,
		"c hs traffic",
		transcriptHash[:],
		32,
	)
	if err != nil {
		return err
	}
	t.clientHandshakeTrafficSecret = append(t.clientHandshakeTrafficSecret, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(
		buff,
		t.handshakeSecret,
		"s hs traffic",
		transcriptHash[:],
		32,
	)
	if err != nil {
		return err
	}
	t.serverHandshakeTrafficSecret = append(t.serverHandshakeTrafficSecret, buff.B...)
	buff.Reset()

	// Derive keys and IVs
	keyLen := t.cipher.KeyLen()
	_, err = hkdfExpandLabel(buff, t.clientHandshakeTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.clientHandshakeKey = append(t.clientHandshakeKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, t.serverHandshakeTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.serverHandshakeKey = append(t.serverHandshakeKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, t.clientHandshakeTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.clientHandshakeIV = append(t.clientHandshakeIV, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, t.serverHandshakeTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.serverHandshakeIV = append(t.serverHandshakeIV, buff.B...)

	// Reset record counters
	t.clientRecordCount = 0
	t.serverRecordCount = 0

	return nil
}

// calculateApplicationKeys derives the application traffic keys
func (t *TLState) calculateApplicationKeys() error {

	transcript := t.handshakeMessages.Bytes()
	transcriptHash := sha256.Sum256(transcript)

	emptyHash := sha256.Sum256(nil)

	buff := byteBuffer.Get()
	defer byteBuffer.Put(buff)

	// derivedSecret
	_, err := hkdfExpandLabel(
		buff,
		t.handshakeSecret,
		"derived",
		emptyHash[:], // empty context per RFC8446 §7.1
		32,
	)
	if err != nil {
		return err
	}

	zeros := make([]byte, sha256.Size) // Escapes to heap
	hkdfExtract(buff, zeros)
	masterSecret := make([]byte, 0, 32)
	masterSecret = append(masterSecret, buff.B...)
	buff.Reset()

	// t.clientApplicationTrafficSecret
	_, err = hkdfExpandLabel(
		buff,
		masterSecret,
		"c ap traffic",
		transcriptHash[:],
		32,
	)
	if err != nil {
		return err
	}
	t.clientApplicationTrafficSecret = append(t.clientApplicationTrafficSecret, buff.B...)
	buff.Reset()

	// t.serverApplicationTrafficSecret
	_, err = hkdfExpandLabel(
		buff,
		masterSecret,
		"s ap traffic",
		transcriptHash[:],
		32,
	)
	if err != nil {
		return err
	}
	t.serverApplicationTrafficSecret = append(t.serverApplicationTrafficSecret, buff.B...)
	buff.Reset()

	keyLen := t.cipher.KeyLen()
	_, err = hkdfExpandLabel(buff, t.clientApplicationTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.clientApplicationKey = append(t.clientApplicationKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, t.serverApplicationTrafficSecret, "key", nil, keyLen)
	if err != nil {
		return err
	}
	t.serverApplicationKey = append(t.serverApplicationKey, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, t.clientApplicationTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.clientApplicationIV = append(t.clientApplicationIV, buff.B...)
	buff.Reset()

	_, err = hkdfExpandLabel(buff, t.serverApplicationTrafficSecret, "iv", nil, 12)
	if err != nil {
		return err
	}
	t.serverApplicationIV = append(t.serverApplicationIV, buff.B...)
	buff.Reset()

	t.clientRecordCount = 0
	t.serverRecordCount = 0

	t.handshakeState = HandshakeStateDone

	return nil
}

// We can fail in here but for now silently failing seems like a better option than to bail out.
func (t *TLState) processApplicationData(out *byteBuffer.ByteBuffer) ResponseState {
	for {

		buffered := t.incoming.Buffered()
		if buffered < 5 {
			return None
		}

		head, tail := t.incoming.Peek(5)
		recType := RecordType(head[0])

		b0 := GetHeadTail(2, head[1:], tail)
		b1 := GetHeadTail(3, head[1:], tail)

		length := int(binary.BigEndian.Uint16([]byte{b0, b1}))

		if buffered < 5+length {
			return None
		}

		headerHead, headerTail := t.incoming.Peek(5)
		t.incoming.Discard(5)

		head, tail = t.incoming.Peek(length)
		t.incoming.Discard(length)

		// Instead of just writing the result into the buffer we can temporarily use it to get rid of 1 heap allocated slice
		// We write recordData into the out buffer temporarily
		out.Reset()
		out.Write(head)
		out.Write(tail)

		// This is getting really fucking hacky. Since we know the header is of length 5 and the clientIV is of length 12, we can
		// just write to out and use windows to the backing slice instead, to avoid 2 heap allocs
		cipherLength := out.Len()

		out.Write(headerHead)
		out.Write(headerTail)

		if recType != RecordTypeApplicationData {
			log.Debug().Uint8("record_type", uint8(recType)).Msg("Skipping non-application-data record")
			continue
		}

		out.Write(t.clientApplicationIV)
		nonce := out.B[cipherLength+5:]

		seq := make([]byte, 8)
		binary.BigEndian.PutUint64(seq, t.clientRecordCount)
		for i := 0; i < 8; i++ {
			nonce[4+i] ^= seq[i]
		}
		t.clientRecordCount++

		if t.clientCipher == nil {
			aead, err := t.createAEAD(t.clientApplicationKey)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create AEAD cipher")
				continue
			}
			t.clientCipher = aead
		}

		plaintext, err := t.clientCipher.Open(
			nil,
			nonce,
			out.B[:cipherLength],
			out.B[cipherLength:cipherLength+5],
		)
		if err != nil {
			log.Error().
				Err(err).
				Uint64("record_count", t.clientRecordCount-1).
				Hex("nonce", nonce).
				Msg("Failed to decrypt application data")
			continue
		}

		if len(plaintext) == 0 {
			log.Warn().Msg("Empty plaintext after decryption")
			continue
		}
		contentType := RecordType(plaintext[len(plaintext)-1])
		plaintext = plaintext[:len(plaintext)-1]

		if contentType == RecordTypeApplicationData {

			// Fullfilled its temporary use, now write the output
			out.Reset()
			out.Write(plaintext)
			return Responded
		}
		log.Debug().Uint8("content_type", uint8(contentType)).Msg("Skipping non-application content type")
	}
}

// Write application data into buff. Data in buff will be whiped. Read encrypted data from buff after function call
func (t *TLState) encryptApplicationData(buff *byteBuffer.ByteBuffer) error {
	buff.WriteByte(byte(RecordTypeApplicationData))

	dataLength := buff.Len()

	recordLength := dataLength + 16 // Add 16 for auth tag

	buff.Write(t.serverApplicationIV)
	nonce := buff.B[dataLength:]

	buff.Write(marshallAdditionalData(recordLength))
	additionalData := buff.B[dataLength+12:]

	// XOR the last bytes with the record count
	nonceCount := make([]byte, 8) // Escapes to heap
	binary.BigEndian.PutUint64(nonceCount, t.serverRecordCount)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= nonceCount[i]
	}
	t.serverRecordCount++

	if t.serverCipher == nil {
		aead, err := t.createAEAD(t.serverApplicationKey)
		if err != nil {
			return err
		}

		t.serverCipher = aead
	}

	ciphertext := t.serverCipher.Seal(
		nil,
		nonce,
		buff.B[:dataLength],
		additionalData,
	)

	// At this point we have read everything we needed into our stack.
	// We re-use our input buffer to return needed data.
	// Ideally this would mean nothing gets pushed to heap, however calling aead.Seal
	// automatically pushes everything to heap since it's an interface
	buff.Reset()

	buff.Write(additionalData)
	buff.Write(ciphertext)

	return nil
}

// Key derivation helper functions

func hkdfExtract(saltInOut *byteBuffer.ByteBuffer, ikm []byte) ResponseState {
	h := hmac.New(sha256.New, saltInOut.B)
	saltInOut.Reset()
	h.Write(ikm)
	saltInOut.Write(h.Sum(nil))

	return Responded
}

func hkdfExpandLabel(out *byteBuffer.ByteBuffer, secret []byte, label string, context []byte, length int) (ResponseState, error) {

	// This isnt our actual output but we can temporarily use it here to avoid a heap escape
	out.Write([]byte{
		byte(length >> 8), byte(length),
	})

	labelWithPrefix := []byte("tls13 " + label)

	out.WriteByte(byte(len(labelWithPrefix)))
	out.Write(labelWithPrefix)

	out.WriteByte(byte(len(context)))
	out.Write(context)

	expander := hkdf.Expand(sha256.New, secret, out.B)

	out.Reset()
	out.B = EnsureLen(out.B, length)

	_, err := io.ReadFull(expander, out.B)
	if err != nil {
		return None, err
	}

	return Responded, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
