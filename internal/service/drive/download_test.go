package drive

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
)

func TestRevisionManifestUsesThumbnailThenOrderedBlockHashes(t *testing.T) {
	thumbnail := sha256.Sum256([]byte("thumbnail"))
	block1 := sha256.Sum256([]byte("block-1"))
	block2 := sha256.Sum256([]byte("block-2"))

	manifest, hashes, err := revisionManifest(
		[]revisionThumbnail{{Hash: base64.StdEncoding.EncodeToString(thumbnail[:])}},
		[]revisionBlock{
			{Index: 1, Hash: base64.StdEncoding.EncodeToString(block1[:])},
			{Index: 2, Hash: base64.StdEncoding.EncodeToString(block2[:])},
		},
	)
	if err != nil {
		t.Fatalf("revisionManifest: %v", err)
	}
	want := append(append(append([]byte{}, thumbnail[:]...), block1[:]...), block2[:]...)
	if string(manifest) != string(want) {
		t.Error("manifest did not contain thumbnail and block hashes in Proton order")
	}
	if len(hashes) != 2 || string(hashes[0]) != string(block1[:]) || string(hashes[1]) != string(block2[:]) {
		t.Error("block hashes did not retain block order")
	}
}

func TestRevisionManifestRejectsGapAndInvalidHash(t *testing.T) {
	valid := sha256.Sum256([]byte("valid"))
	if _, _, err := revisionManifest(nil, []revisionBlock{{Index: 2, Hash: base64.StdEncoding.EncodeToString(valid[:])}}); err == nil {
		t.Error("revisionManifest accepted a missing first block")
	}
	if _, _, err := revisionManifest(nil, []revisionBlock{{Index: 1, Hash: base64.StdEncoding.EncodeToString([]byte("short"))}}); err == nil {
		t.Error("revisionManifest accepted a non-SHA-256 hash")
	}
}

func TestVerifyBlockHashUsesEncryptedBytes(t *testing.T) {
	encrypted := []byte("encrypted block")
	hash := sha256.Sum256(encrypted)
	if err := verifyBlockHash(encrypted, hash[:]); err != nil {
		t.Fatalf("verifyBlockHash: %v", err)
	}
	if err := verifyBlockHash([]byte("changed"), hash[:]); err == nil {
		t.Error("verifyBlockHash accepted changed encrypted bytes")
	}
}

func TestVerifyManifestRequiresValidSignature(t *testing.T) {
	key, err := pgp.GenerateKey("Node", "", "x25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	keyRing, err := pgp.NewKeyRing(key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("manifest hashes")
	signature, err := keyRing.SignDetached(pgp.NewPlainMessage(manifest))
	if err != nil {
		t.Fatal(err)
	}
	armored, err := signature.GetArmored()
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil)
	if err := s.verifyManifest(context.Background(), keyRing, "", manifest, armored); err != nil {
		t.Fatalf("verifyManifest: %v", err)
	}
	if err := s.verifyManifest(context.Background(), keyRing, "", []byte("changed"), armored); err == nil {
		t.Error("verifyManifest accepted a signature over different data")
	}
	if err := s.verifyManifest(context.Background(), keyRing, "", manifest, ""); err == nil {
		t.Error("verifyManifest accepted a missing signature")
	}
}

func TestVerifyContentKeyPacketAcceptsNodeSignature(t *testing.T) {
	key, err := pgp.GenerateKey("Node", "", "x25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	keyRing, err := pgp.NewKeyRing(key)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey, err := pgp.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := keyRing.SignDetached(pgp.NewPlainMessage(sessionKey.Key))
	if err != nil {
		t.Fatal(err)
	}
	armored, err := signature.GetArmored()
	if err != nil {
		t.Fatal(err)
	}
	link := &Link{}
	link.FileProperties = &struct {
		ContentKeyPacket          string
		ContentKeyPacketSignature string
		ActiveRevision            struct {
			ID    string
			Photo struct {
				ContentHash          string
				RelatedPhotosLinkIDs []string
			}
		}
	}{ContentKeyPacketSignature: armored}

	s := New(nil)
	if err := s.verifyContentKeyPacket(context.Background(), link, keyRing, sessionKey); err != nil {
		t.Fatalf("verifyContentKeyPacket: %v", err)
	}
	link.FileProperties.ContentKeyPacketSignature = ""
	if err := s.verifyContentKeyPacket(context.Background(), link, keyRing, sessionKey); err == nil {
		t.Error("verifyContentKeyPacket accepted a missing signature")
	}
}
