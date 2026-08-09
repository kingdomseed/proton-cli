package pass

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/roman-16/proton-cli/internal/crypto/aead"
	"github.com/roman-16/proton-cli/internal/proton"
	pb "github.com/roman-16/proton-cli/internal/service/pass/proto"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestVaultEditUsesLatestShareKeyAndPreservesContent(t *testing.T) {
	oldKey, err := aead.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	latestKey, err := aead.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	u, shareKeys := testUserAndShareKey(t, map[int][]byte{2: oldKey, 5: latestKey})
	rawVault, err := proto.Marshal(&pb.Vault{Name: "Before", Description: "Keep this"})
	if err != nil {
		t.Fatal(err)
	}
	unknown := protowire.AppendTag(nil, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 42)
	rawVault = append(rawVault, unknown...)
	encVault, err := aead.Encrypt(oldKey, rawVault, []byte(aead.TagVaultContent))
	if err != nil {
		t.Fatal(err)
	}

	var update proton.Request
	d := &scriptedDoer{handler: func(req proton.Request) (any, error) {
		switch req.Path {
		case "/pass/v1/share":
			return map[string]any{"Shares": []map[string]any{{
				"ShareID": "share-1", "TargetType": 1,
				"Content": base64.StdEncoding.EncodeToString(encVault), "ContentKeyRotation": 2,
			}}}, nil
		case "/pass/v1/share/share-1/key":
			return map[string]any{"ShareKeys": map[string]any{"Keys": shareKeys}}, nil
		case "/pass/v1/vault/share-1":
			update = req
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.Path)
		}
	}}

	if err := New(d).VaultEdit(context.Background(), u, "share-1", "After"); err != nil {
		t.Fatalf("VaultEdit: %v", err)
	}
	body := update.Body.(map[string]any)
	if got := body["KeyRotation"]; got != 5 {
		t.Fatalf("KeyRotation = %v, want 5", got)
	}
	encoded, ok := body["Content"].(string)
	if !ok {
		t.Fatalf("Content has type %T", body["Content"])
	}
	got, err := decryptVault(encoded, latestKey)
	if err != nil {
		t.Fatalf("decrypt updated vault: %v", err)
	}
	if got.Name != "After" || got.Description != "Keep this" {
		t.Errorf("updated vault = %#v", got)
	}
	if string(got.ProtoReflect().GetUnknown()) != string(unknown) {
		t.Error("VaultEdit did not preserve unknown protobuf fields")
	}
}

func TestVaultEditStopsWhenExistingContentCannotDecrypt(t *testing.T) {
	key, err := aead.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	u, shareKeys := testUserAndShareKey(t, map[int][]byte{2: key})
	d := &scriptedDoer{handler: func(req proton.Request) (any, error) {
		switch req.Path {
		case "/pass/v1/share":
			return map[string]any{"Shares": []map[string]any{{
				"ShareID": "share-1", "TargetType": 1, "Content": "invalid", "ContentKeyRotation": 2,
			}}}, nil
		case "/pass/v1/share/share-1/key":
			return map[string]any{"ShareKeys": map[string]any{"Keys": shareKeys}}, nil
		default:
			return nil, fmt.Errorf("unexpected mutation: %s %s", req.Method, req.Path)
		}
	}}

	if err := New(d).VaultEdit(context.Background(), u, "share-1", "After"); err == nil {
		t.Fatal("VaultEdit accepted content that it could not decrypt")
	}
	for _, req := range d.reqs {
		if req.Method == "PUT" {
			t.Error("VaultEdit sent a mutation after a content error")
		}
	}
}
