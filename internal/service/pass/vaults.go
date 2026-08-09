package pass

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/roman-16/proton-cli/internal/account/keys"
	"github.com/roman-16/proton-cli/internal/crypto/aead"
	"github.com/roman-16/proton-cli/internal/errs"
	"github.com/roman-16/proton-cli/internal/proton"
	pb "github.com/roman-16/proton-cli/internal/service/pass/proto"
	"google.golang.org/protobuf/proto"
)

type Vault struct {
	ShareID     string `json:"share_id"`
	VaultID     string `json:"vault_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Owner       bool   `json:"owner"`
	Shared      bool   `json:"shared"`
	Members     int    `json:"members"`
	AddressID   string `json:"address_id,omitempty"`
}

func (s *Service) VaultsList(ctx context.Context, u *keys.Unlocked) ([]Vault, error) {
	shares, err := s.getShares(ctx)
	if err != nil {
		return nil, err
	}
	var out []Vault
	for _, raw := range shares {
		var sh struct {
			ShareID            string
			VaultID            string
			TargetType         int
			Owner              bool
			Shared             bool
			TargetMembers      int
			AddressID          string
			Content            string
			ContentKeyRotation int
		}
		if err := json.Unmarshal(raw, &sh); err != nil {
			continue
		}
		if sh.TargetType != 1 {
			continue
		}
		v := Vault{
			ShareID: sh.ShareID, VaultID: sh.VaultID,
			Owner: sh.Owner, Shared: sh.Shared,
			Members: sh.TargetMembers, AddressID: sh.AddressID,
		}
		if sh.Content != "" {
			sk, err := s.decryptShareKeys(ctx, sh.ShareID, u)
			if err == nil {
				if key, ok := sk.keys[sh.ContentKeyRotation]; ok {
					if vv, err := decryptVault(sh.Content, key); err == nil {
						v.Name = vv.Name
						v.Description = vv.Description
					}
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) VaultCreate(ctx context.Context, u *keys.Unlocked, name string) (string, error) {
	vault := &pb.Vault{Name: name}
	rawKey, err := aead.NewKey()
	if err != nil {
		return "", err
	}
	msg := pgp.NewPlainMessage(rawKey)
	encKey, err := u.UserKR.Encrypt(msg, u.UserKR)
	if err != nil {
		return "", err
	}
	encVaultKey := base64.StdEncoding.EncodeToString(encKey.GetBinary())
	pbBytes, err := proto.Marshal(vault)
	if err != nil {
		return "", err
	}
	ct, err := aead.Encrypt(rawKey, pbBytes, []byte(aead.TagVaultContent))
	if err != nil {
		return "", err
	}
	_, addr, err := u.PrimaryAddr()
	if err != nil {
		return "", err
	}
	var r struct{ Share struct{ ShareID string } }
	if err := s.C.Decode(ctx, proton.Request{
		Method: "POST", Path: "/pass/v1/vault",
		Body: map[string]any{
			"AddressID":            addr.ID,
			"ContentFormatVersion": 1,
			"Content":              base64.StdEncoding.EncodeToString(ct),
			"EncryptedVaultKey":    encVaultKey,
		},
	}, &r); err != nil {
		return "", err
	}
	return r.Share.ShareID, nil
}

func (s *Service) VaultDelete(ctx context.Context, shareID string) error {
	return s.C.Decode(ctx, proton.Request{Method: "DELETE", Path: "/pass/v1/vault/" + shareID}, nil)
}

// VaultEdit renames a vault, preserving its description and display settings by
// re-encrypting the existing vault content with the latest share key.
func (s *Service) VaultEdit(ctx context.Context, u *keys.Unlocked, shareID, newName string) error {
	shares, err := s.getShares(ctx)
	if err != nil {
		return err
	}
	var content string
	var rotation int
	found := false
	for _, raw := range shares {
		var sh struct {
			ShareID            string
			TargetType         int
			Content            string
			ContentKeyRotation int
		}
		if err := json.Unmarshal(raw, &sh); err != nil {
			continue
		}
		if sh.ShareID == shareID && sh.TargetType == 1 {
			content, rotation, found = sh.Content, sh.ContentKeyRotation, true
			break
		}
	}
	if !found {
		return &errs.NotFound{Kind: "vault", Ref: shareID}
	}
	sk, err := s.decryptShareKeys(ctx, shareID, u)
	if err != nil {
		return err
	}
	shareKey, ok := sk.keys[rotation]
	if !ok {
		return fmt.Errorf("no share key for rotation %d", rotation)
	}
	if content == "" {
		return fmt.Errorf("vault %s has no encrypted content", shareID)
	}
	vault, err := decryptVault(content, shareKey)
	if err != nil {
		return fmt.Errorf("decrypt vault content: %w", err)
	}
	vault.Name = newName
	latestKey, latestRotation := sk.latest()
	if latestKey == nil {
		return fmt.Errorf("vault %s has no usable share key", shareID)
	}
	pbBytes, err := proto.Marshal(vault)
	if err != nil {
		return err
	}
	ct, err := aead.Encrypt(latestKey, pbBytes, []byte(aead.TagVaultContent))
	if err != nil {
		return err
	}
	return s.C.Decode(ctx, proton.Request{
		Method: "PUT", Path: "/pass/v1/vault/" + shareID,
		Body: map[string]any{
			"Content":              base64.StdEncoding.EncodeToString(ct),
			"ContentFormatVersion": 1,
			"KeyRotation":          latestRotation,
		},
	}, nil)
}

func (s *Service) ResolveVault(ctx context.Context, u *keys.Unlocked, nameOrID string) (string, error) {
	vaults, err := s.VaultsList(ctx, u)
	if err != nil {
		return "", err
	}
	if nameOrID == "" {
		if len(vaults) == 0 {
			return "", &errs.NotFound{Kind: "vault"}
		}
		return vaults[0].ShareID, nil
	}
	for _, v := range vaults {
		if v.ShareID == nameOrID {
			return v.ShareID, nil
		}
	}
	for _, v := range vaults {
		if v.Name == nameOrID {
			return v.ShareID, nil
		}
	}
	return "", &errs.NotFound{Kind: "vault", Ref: nameOrID}
}

func decryptVault(encContent string, shareKey []byte) (*pb.Vault, error) {
	data, err := base64.StdEncoding.DecodeString(encContent)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Decrypt(shareKey, data, []byte(aead.TagVaultContent))
	if err != nil {
		return nil, err
	}
	var v pb.Vault
	if err := proto.Unmarshal(plain, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
