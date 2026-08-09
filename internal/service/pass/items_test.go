package pass

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/roman-16/proton-cli/internal/account/keys"
	"github.com/roman-16/proton-cli/internal/crypto/aead"
	"github.com/roman-16/proton-cli/internal/proton"
	pb "github.com/roman-16/proton-cli/internal/service/pass/proto"
	"google.golang.org/protobuf/proto"
)

type scriptedDoer struct {
	reqs    []proton.Request
	handler func(proton.Request) (any, error)
}

func (d *scriptedDoer) Do(context.Context, proton.Request) (*proton.Response, error) {
	return nil, fmt.Errorf("unexpected Do call")
}

func (d *scriptedDoer) Decode(_ context.Context, req proton.Request, out any) error {
	d.reqs = append(d.reqs, req)
	value, err := d.handler(req)
	if err != nil || out == nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func testUserAndShareKey(t *testing.T, rotations map[int][]byte) (*keys.Unlocked, []map[string]any) {
	t.Helper()
	userKey, err := pgp.GenerateKey("Test", "test@example.com", "x25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	userKR, err := pgp.NewKeyRing(userKey)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, 0, len(rotations))
	for rotation, shareKey := range rotations {
		enc, err := userKR.Encrypt(pgp.NewPlainMessage(shareKey), userKR)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]any{
			"Key":         base64.StdEncoding.EncodeToString(enc.GetBinary()),
			"KeyRotation": rotation,
		})
	}
	return &keys.Unlocked{UserKR: userKR}, out
}

func TestItemEditUsesRevisionKeyRotation(t *testing.T) {
	shareKey, err := aead.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	itemKey, err := aead.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	u, shareKeys := testUserAndShareKey(t, map[int][]byte{4: shareKey})

	encItemKey, err := aead.Encrypt(shareKey, itemKey, []byte(aead.TagItemKey))
	if err != nil {
		t.Fatal(err)
	}
	rawItem, err := proto.Marshal(&pb.Item{Metadata: &pb.Metadata{Name: "Before"}})
	if err != nil {
		t.Fatal(err)
	}
	encContent, err := aead.Encrypt(itemKey, rawItem, []byte(aead.TagItemContent))
	if err != nil {
		t.Fatal(err)
	}

	var update proton.Request
	d := &scriptedDoer{handler: func(req proton.Request) (any, error) {
		switch req.Path {
		case "/pass/v1/share/share-1/key":
			return map[string]any{"ShareKeys": map[string]any{"Keys": shareKeys}}, nil
		case "/pass/v1/share/share-1/item/item-1":
			if req.Method == "GET" {
				return map[string]any{"Item": map[string]any{
					"Revision": 9, "Content": base64.StdEncoding.EncodeToString(encContent),
					"ItemKey": base64.StdEncoding.EncodeToString(encItemKey), "KeyRotation": 4,
				}}, nil
			}
			update = req
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.Path)
		}
	}}

	if err := New(d).ItemEdit(context.Background(), u, "share-1", "item-1", Patch{Name: "After"}); err != nil {
		t.Fatalf("ItemEdit: %v", err)
	}
	body, ok := update.Body.(map[string]any)
	if !ok {
		t.Fatalf("update body has type %T", update.Body)
	}
	if got := body["KeyRotation"]; got != 4 {
		t.Errorf("KeyRotation = %v, want 4", got)
	}
	if got := body["LastRevision"]; got != 9 {
		t.Errorf("LastRevision = %v, want 9", got)
	}
	updatedContent, ok := body["Content"].(string)
	if !ok {
		t.Fatalf("Content has type %T", body["Content"])
	}
	updatedBytes, err := base64.StdEncoding.DecodeString(updatedContent)
	if err != nil {
		t.Fatal(err)
	}
	updatedPlain, err := aead.Decrypt(itemKey, updatedBytes, []byte(aead.TagItemContent))
	if err != nil {
		t.Fatalf("decrypt updated item content: %v", err)
	}
	var updatedItem pb.Item
	if err := proto.Unmarshal(updatedPlain, &updatedItem); err != nil {
		t.Fatal(err)
	}
	if updatedItem.GetMetadata().GetName() != "After" {
		t.Errorf("updated item name = %q, want After", updatedItem.GetMetadata().GetName())
	}
	for _, req := range d.reqs {
		if req.Path == "/pass/v1/share/share-1/item/item-1/key/latest" {
			t.Error("ItemEdit must not request a different item-key rotation")
		}
	}
}

func TestItemEditRejectsInvalidEncodedItemKey(t *testing.T) {
	shareKey, err := aead.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	u, shareKeys := testUserAndShareKey(t, map[int][]byte{2: shareKey})
	d := &scriptedDoer{handler: func(req proton.Request) (any, error) {
		if req.Path == "/pass/v1/share/share-1/key" {
			return map[string]any{"ShareKeys": map[string]any{"Keys": shareKeys}}, nil
		}
		return map[string]any{"Item": map[string]any{
			"Revision": 1, "ItemKey": "not base64", "Content": "not used", "KeyRotation": 2,
		}}, nil
	}}

	err = New(d).ItemEdit(context.Background(), u, "share-1", "item-1", Patch{Name: "After"})
	if err == nil {
		t.Fatal("ItemEdit accepted an invalid encoded item key")
	}
	for _, req := range d.reqs {
		if req.Method == "PUT" {
			t.Error("ItemEdit sent a mutation after an item-key decode error")
		}
	}
}
