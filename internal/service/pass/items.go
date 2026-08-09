package pass

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/roman-16/proton-cli/internal/account/keys"
	"github.com/roman-16/proton-cli/internal/crypto/aead"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/ref"
	pb "github.com/roman-16/proton-cli/internal/service/pass/proto"
	"google.golang.org/protobuf/proto"
)

type Item struct {
	ShareID    string   `json:"share_id"`
	ItemID     string   `json:"item_id"`
	Revision   int      `json:"revision"`
	State      int      `json:"state"`
	Type       string   `json:"type"`
	CreateTime int64    `json:"create_time,omitempty"`
	ModifyTime int64    `json:"modify_time,omitempty"`
	Name       string   `json:"name,omitempty"`
	Note       string   `json:"note,omitempty"`
	Username   string   `json:"username,omitempty"`
	Email      string   `json:"email,omitempty"`
	Password   string   `json:"password,omitempty"`
	TOTP       string   `json:"totp,omitempty"`
	URLs       []string `json:"urls,omitempty"`
	Holder     string   `json:"holder,omitempty"`
	Number     string   `json:"number,omitempty"`
	Expiry     string   `json:"expiry,omitempty"`
	CVV        string   `json:"cvv,omitempty"`
	PIN        string   `json:"pin,omitempty"`
	SSID       string   `json:"ssid,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
	PrivateKey string   `json:"private_key,omitempty"`

	// identity
	FullName      string `json:"full_name,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
	Phone         string `json:"phone,omitempty"`
	Organization  string `json:"organization,omitempty"`
	JobTitle      string `json:"job_title,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	City          string `json:"city,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
	Birthdate     string `json:"birthdate,omitempty"`
	Website       string `json:"website,omitempty"`

	// extra custom fields (any item type)
	Fields []ItemField `json:"fields,omitempty"`

	raw *pb.Item
}

// ItemField is a custom extra field attached to an item.
type ItemField struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Type  string `json:"type"`
}

func (s *Service) ItemsList(ctx context.Context, u *keys.Unlocked, vaultFilter string) ([]Item, error) {
	vaults, err := s.VaultsList(ctx, u)
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, v := range vaults {
		if vaultFilter != "" && v.ShareID != vaultFilter && v.Name != vaultFilter {
			continue
		}
		sk, err := s.decryptShareKeys(ctx, v.ShareID, u)
		if err != nil {
			continue
		}
		items, err := s.fetchItems(ctx, v.ShareID, sk)
		if err != nil {
			continue
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *Service) ItemGet(ctx context.Context, u *keys.Unlocked, shareID, itemID string) (*Item, error) {
	sk, err := s.decryptShareKeys(ctx, shareID, u)
	if err != nil {
		return nil, err
	}
	var r struct {
		Item struct {
			ItemID           string
			Revision         int
			State            int
			Content, ItemKey string
			KeyRotation      int
			CreateTime       int64
			ModifyTime       int64
		}
	}
	if err := s.C.Decode(ctx, proton.Request{Method: "GET", Path: fmt.Sprintf("/pass/v1/share/%s/item/%s", shareID, itemID)}, &r); err != nil {
		return nil, err
	}
	shareKey, ok := sk.keys[r.Item.KeyRotation]
	if !ok {
		return nil, fmt.Errorf("no share key for rotation %d", r.Item.KeyRotation)
	}
	ikBytes, err := base64.StdEncoding.DecodeString(r.Item.ItemKey)
	if err != nil {
		return nil, err
	}
	itemKey, err := aead.Decrypt(shareKey, ikBytes, []byte(aead.TagItemKey))
	if err != nil {
		return nil, err
	}
	cBytes, err := base64.StdEncoding.DecodeString(r.Item.Content)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Decrypt(itemKey, cBytes, []byte(aead.TagItemContent))
	if err != nil {
		return nil, err
	}
	var it pb.Item
	if err := proto.Unmarshal(plain, &it); err != nil {
		return nil, err
	}
	out := itemFromProto(&it)
	out.ShareID = shareID
	out.ItemID = r.Item.ItemID
	out.Revision = r.Item.Revision
	out.State = r.Item.State
	out.CreateTime = r.Item.CreateTime
	out.ModifyTime = r.Item.ModifyTime
	return out, nil
}

func (s *Service) ResolveItem(ctx context.Context, u *keys.Unlocked, args []string) (string, string, error) {
	if len(args) == 2 {
		return args[0], args[1], nil
	}
	needle := strings.ToLower(args[0])
	items, err := s.ItemsList(ctx, u, "")
	if err != nil {
		return "", "", err
	}
	// An exact item-ID match wins outright, so the ID printed by `items create`
	// round-trips as a single REF to get/edit/delete.
	for _, it := range items {
		if it.ItemID == args[0] {
			return it.ShareID, it.ItemID, nil
		}
	}
	var matches []Item
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Name), needle) {
			matches = append(matches, it)
			continue
		}
		for _, url := range it.URLs {
			if strings.Contains(strings.ToLower(url), needle) {
				matches = append(matches, it)
				break
			}
		}
	}
	it, err := ref.Pick("item", args[0], matches,
		func(i Item) string { return i.ItemID },
		func(i Item) string { return fmt.Sprintf("%s  %s  (share %s)", i.Type, i.Name, i.ShareID) })
	if err != nil {
		return "", "", err
	}
	return it.ShareID, it.ItemID, nil
}

type NewItem struct {
	Type                                       string
	Name, Username, Password, Email, URL, Note string
	TOTP                                       string
	Holder, Number, Expiry, CVV, PIN           string
	SSID, WifiSecurity                         string
	PrivateKey, PublicKey                      string
	// identity
	FullName, FirstName, LastName, PhoneNumber string
	Organization, JobTitle                     string
	StreetAddress, City, PostalCode, Country   string
	Birthdate, Website                         string
	// extra custom fields, each "NAME=VALUE"
	Fields       []string
	HiddenFields []string
}

func buildExtraFields(textFields, hiddenFields []string) ([]*pb.ExtraField, error) {
	var out []*pb.ExtraField
	for _, f := range textFields {
		name, val, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --field %q (expected NAME=VALUE)", f)
		}
		out = append(out, &pb.ExtraField{FieldName: name, Content: &pb.ExtraField_Text{Text: &pb.ExtraTextField{Content: val}}})
	}
	for _, f := range hiddenFields {
		name, val, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --hidden %q (expected NAME=VALUE)", f)
		}
		out = append(out, &pb.ExtraField{FieldName: name, Content: &pb.ExtraField_Hidden{Hidden: &pb.ExtraHiddenField{Content: val}}})
	}
	return out, nil
}

func extraFieldToItem(f *pb.ExtraField) ItemField {
	switch c := f.Content.(type) {
	case *pb.ExtraField_Text:
		return ItemField{Name: f.FieldName, Value: c.Text.Content, Type: "text"}
	case *pb.ExtraField_Hidden:
		return ItemField{Name: f.FieldName, Value: c.Hidden.Content, Type: "hidden"}
	case *pb.ExtraField_Totp:
		return ItemField{Name: f.FieldName, Value: c.Totp.TotpUri, Type: "totp"}
	}
	return ItemField{Name: f.FieldName, Type: "unknown"}
}

// wifiSecurity maps a CLI security string to the protobuf enum; an unknown or
// empty value falls back to unspecified.
func wifiSecurity(s string) pb.WifiSecurity {
	switch strings.ToUpper(s) {
	case "WPA":
		return pb.WifiSecurity_WPA
	case "WPA2":
		return pb.WifiSecurity_WPA2
	case "WPA3":
		return pb.WifiSecurity_WPA3
	case "WEP":
		return pb.WifiSecurity_WEP
	default:
		return pb.WifiSecurity_UnspecifiedWifiSecurity
	}
}

func (s *Service) ItemCreate(ctx context.Context, u *keys.Unlocked, shareID string, nc NewItem) (string, error) {
	sk, err := s.decryptShareKeys(ctx, shareID, u)
	if err != nil {
		return "", err
	}
	shareKey, rotation := sk.latest()

	item := &pb.Item{Metadata: &pb.Metadata{Name: nc.Name, Note: nc.Note}, Content: &pb.Content{}}
	switch nc.Type {
	case "login":
		urls := []string{}
		if nc.URL != "" {
			urls = append(urls, nc.URL)
		}
		item.Content.Content = &pb.Content_Login{Login: &pb.ItemLogin{
			ItemUsername: nc.Username, ItemEmail: nc.Email, Password: nc.Password, Urls: urls, TotpUri: nc.TOTP,
		}}
	case "note":
		item.Content.Content = &pb.Content_Note{Note: &pb.ItemNote{}}
	case "credit-card":
		item.Content.Content = &pb.Content_CreditCard{CreditCard: &pb.ItemCreditCard{
			CardholderName: nc.Holder, Number: nc.Number, ExpirationDate: nc.Expiry,
			VerificationNumber: nc.CVV, Pin: nc.PIN,
		}}
	case "wifi":
		item.Content.Content = &pb.Content_Wifi{Wifi: &pb.ItemWifi{
			Ssid: nc.SSID, Password: nc.Password, Security: wifiSecurity(nc.WifiSecurity),
		}}
	case "ssh-key":
		item.Content.Content = &pb.Content_SshKey{SshKey: &pb.ItemSSHKey{
			PrivateKey: nc.PrivateKey, PublicKey: nc.PublicKey,
		}}
	case "identity":
		item.Content.Content = &pb.Content_Identity{Identity: &pb.ItemIdentity{
			FullName: nc.FullName, FirstName: nc.FirstName, LastName: nc.LastName,
			Email: nc.Email, PhoneNumber: nc.PhoneNumber,
			Organization: nc.Organization, JobTitle: nc.JobTitle,
			StreetAddress: nc.StreetAddress, City: nc.City,
			ZipOrPostalCode: nc.PostalCode, CountryOrRegion: nc.Country,
			Birthdate: nc.Birthdate, Website: nc.Website,
		}}
	case "custom":
		item.Content.Content = &pb.Content_Custom{Custom: &pb.ItemCustom{}}
	default:
		return "", fmt.Errorf("unsupported item type %q (supported: login, note, credit-card, wifi, ssh-key, identity, custom)", nc.Type)
	}
	extra, err := buildExtraFields(nc.Fields, nc.HiddenFields)
	if err != nil {
		return "", err
	}
	item.ExtraFields = extra

	itemKey, err := aead.NewKey()
	if err != nil {
		return "", err
	}
	pbBytes, err := proto.Marshal(item)
	if err != nil {
		return "", err
	}
	ct, err := aead.Encrypt(itemKey, pbBytes, []byte(aead.TagItemContent))
	if err != nil {
		return "", err
	}
	ek, err := aead.Encrypt(shareKey, itemKey, []byte(aead.TagItemKey))
	if err != nil {
		return "", err
	}
	var r struct{ Item struct{ ItemID string } }
	if err := s.C.Decode(ctx, proton.Request{
		Method: "POST", Path: "/pass/v1/share/" + shareID + "/item",
		Body: map[string]any{
			"Content":              base64.StdEncoding.EncodeToString(ct),
			"ContentFormatVersion": 7,
			"ItemKey":              base64.StdEncoding.EncodeToString(ek),
			"KeyRotation":          rotation,
		},
	}, &r); err != nil {
		return "", err
	}
	return r.Item.ItemID, nil
}

type Patch struct {
	Name, Username, Password, Email, URL, Note string
	TOTP                                       string
	Holder, Number, Expiry, CVV, PIN           string
	SSID, WifiSecurity                         string
	PrivateKey, PublicKey                      string
	// identity
	FullName, FirstName, LastName, PhoneNumber string
	Organization, JobTitle                     string
	StreetAddress, City, PostalCode, Country   string
	Birthdate, Website                         string
}

func (s *Service) ItemEdit(ctx context.Context, u *keys.Unlocked, shareID, itemID string, patch Patch) error {
	sk, err := s.decryptShareKeys(ctx, shareID, u)
	if err != nil {
		return err
	}
	var r struct {
		Item struct {
			Revision         int
			Content, ItemKey string
			KeyRotation      int
		}
	}
	if err := s.C.Decode(ctx, proton.Request{Method: "GET", Path: fmt.Sprintf("/pass/v1/share/%s/item/%s", shareID, itemID)}, &r); err != nil {
		return err
	}
	shareKey, ok := sk.keys[r.Item.KeyRotation]
	if !ok {
		return fmt.Errorf("no share key for rotation %d", r.Item.KeyRotation)
	}
	ikBytes, err := base64.StdEncoding.DecodeString(r.Item.ItemKey)
	if err != nil {
		return fmt.Errorf("decode item key: %w", err)
	}
	itemKey, err := aead.Decrypt(shareKey, ikBytes, []byte(aead.TagItemKey))
	if err != nil {
		return err
	}
	cBytes, err := base64.StdEncoding.DecodeString(r.Item.Content)
	if err != nil {
		return fmt.Errorf("decode item content: %w", err)
	}
	plain, err := aead.Decrypt(itemKey, cBytes, []byte(aead.TagItemContent))
	if err != nil {
		return err
	}
	var it pb.Item
	if err := proto.Unmarshal(plain, &it); err != nil {
		return err
	}
	if it.Metadata == nil {
		it.Metadata = &pb.Metadata{}
	}
	if patch.Name != "" {
		it.Metadata.Name = patch.Name
	}
	if patch.Note != "" {
		it.Metadata.Note = patch.Note
	}
	if it.Content != nil {
		switch content := it.Content.Content.(type) {
		case *pb.Content_Login:
			l := content.Login
			if patch.Username != "" {
				l.ItemUsername = patch.Username
			}
			if patch.Password != "" {
				l.Password = patch.Password
			}
			if patch.Email != "" {
				l.ItemEmail = patch.Email
			}
			if patch.URL != "" {
				l.Urls = []string{patch.URL}
			}
			if patch.TOTP != "" {
				l.TotpUri = patch.TOTP
			}
		case *pb.Content_CreditCard:
			cc := content.CreditCard
			if patch.Holder != "" {
				cc.CardholderName = patch.Holder
			}
			if patch.Number != "" {
				cc.Number = patch.Number
			}
			if patch.Expiry != "" {
				cc.ExpirationDate = patch.Expiry
			}
			if patch.CVV != "" {
				cc.VerificationNumber = patch.CVV
			}
			if patch.PIN != "" {
				cc.Pin = patch.PIN
			}
		case *pb.Content_Wifi:
			w := content.Wifi
			if patch.SSID != "" {
				w.Ssid = patch.SSID
			}
			if patch.Password != "" {
				w.Password = patch.Password
			}
			if patch.WifiSecurity != "" {
				w.Security = wifiSecurity(patch.WifiSecurity)
			}
		case *pb.Content_SshKey:
			k := content.SshKey
			if patch.PrivateKey != "" {
				k.PrivateKey = patch.PrivateKey
			}
			if patch.PublicKey != "" {
				k.PublicKey = patch.PublicKey
			}
		case *pb.Content_Identity:
			idn := content.Identity
			if patch.FullName != "" {
				idn.FullName = patch.FullName
			}
			if patch.FirstName != "" {
				idn.FirstName = patch.FirstName
			}
			if patch.LastName != "" {
				idn.LastName = patch.LastName
			}
			if patch.Email != "" {
				idn.Email = patch.Email
			}
			if patch.PhoneNumber != "" {
				idn.PhoneNumber = patch.PhoneNumber
			}
			if patch.Organization != "" {
				idn.Organization = patch.Organization
			}
			if patch.JobTitle != "" {
				idn.JobTitle = patch.JobTitle
			}
			if patch.StreetAddress != "" {
				idn.StreetAddress = patch.StreetAddress
			}
			if patch.City != "" {
				idn.City = patch.City
			}
			if patch.PostalCode != "" {
				idn.ZipOrPostalCode = patch.PostalCode
			}
			if patch.Country != "" {
				idn.CountryOrRegion = patch.Country
			}
			if patch.Birthdate != "" {
				idn.Birthdate = patch.Birthdate
			}
			if patch.Website != "" {
				idn.Website = patch.Website
			}
		}
	}
	pbBytes, err := proto.Marshal(&it)
	if err != nil {
		return err
	}
	ct, err := aead.Encrypt(itemKey, pbBytes, []byte(aead.TagItemContent))
	if err != nil {
		return err
	}
	return s.C.Decode(ctx, proton.Request{
		Method: "PUT", Path: fmt.Sprintf("/pass/v1/share/%s/item/%s", shareID, itemID),
		Body: map[string]any{
			"Content":              base64.StdEncoding.EncodeToString(ct),
			"ContentFormatVersion": 7,
			"KeyRotation":          r.Item.KeyRotation,
			"LastRevision":         r.Item.Revision,
		},
	}, nil)
}

func (s *Service) ItemTrash(ctx context.Context, shareID, itemID string) error {
	rev, err := s.itemRevision(ctx, shareID, itemID)
	if err != nil {
		return err
	}
	return s.C.Decode(ctx, proton.Request{
		Method: "POST", Path: "/pass/v1/share/" + shareID + "/item/trash",
		Body: map[string]any{"Items": []map[string]any{{"ItemID": itemID, "Revision": rev}}},
	}, nil)
}

func (s *Service) ItemRestore(ctx context.Context, shareID, itemID string) error {
	rev, err := s.itemRevision(ctx, shareID, itemID)
	if err != nil {
		return err
	}
	return s.C.Decode(ctx, proton.Request{
		Method: "POST", Path: "/pass/v1/share/" + shareID + "/item/untrash",
		Body: map[string]any{"Items": []map[string]any{{"ItemID": itemID, "Revision": rev}}},
	}, nil)
}

// ItemDelete must trash an active item first; the API rejects deleting one
// that isn't already in the trash.
func (s *Service) ItemDelete(ctx context.Context, shareID, itemID string) error {
	var r struct {
		Item struct {
			Revision int
			State    int
		}
	}
	if err := s.C.Decode(ctx, proton.Request{Method: "GET", Path: fmt.Sprintf("/pass/v1/share/%s/item/%s", shareID, itemID)}, &r); err != nil {
		return err
	}
	if r.Item.State != 2 {
		if err := s.ItemTrash(ctx, shareID, itemID); err != nil {
			return err
		}
		if err := s.C.Decode(ctx, proton.Request{Method: "GET", Path: fmt.Sprintf("/pass/v1/share/%s/item/%s", shareID, itemID)}, &r); err != nil {
			return err
		}
	}
	return s.C.Decode(ctx, proton.Request{
		Method: "DELETE", Path: "/pass/v1/share/" + shareID + "/item",
		Body: map[string]any{"Items": []map[string]any{{"ItemID": itemID, "Revision": r.Item.Revision}}},
	}, nil)
}

func (s *Service) itemRevision(ctx context.Context, shareID, itemID string) (int, error) {
	var r struct{ Item struct{ Revision int } }
	if err := s.C.Decode(ctx, proton.Request{Method: "GET", Path: fmt.Sprintf("/pass/v1/share/%s/item/%s", shareID, itemID)}, &r); err != nil {
		return 0, err
	}
	return r.Item.Revision, nil
}

func (s *Service) fetchItems(ctx context.Context, shareID string, sk *shareKeys) ([]Item, error) {
	var out []Item
	var since string
	for {
		qv := proton.Query()
		if since != "" {
			qv.Set("Since", since)
		}
		var r struct {
			Items struct {
				RevisionsData []json.RawMessage
				LastToken     string
			}
		}
		if err := s.C.Decode(ctx, proton.Request{Method: "GET", Path: "/pass/v1/share/" + shareID + "/item", Query: qv}, &r); err != nil {
			return nil, err
		}
		for _, raw := range r.Items.RevisionsData {
			var enc struct {
				ItemID           string
				Revision         int
				State            int
				Content, ItemKey string
				KeyRotation      int
				CreateTime       int64
				ModifyTime       int64
			}
			if err := json.Unmarshal(raw, &enc); err != nil {
				continue
			}
			if enc.State != 1 {
				continue
			}
			shareKey, ok := sk.keys[enc.KeyRotation]
			if !ok {
				continue
			}
			ikBytes, err := base64.StdEncoding.DecodeString(enc.ItemKey)
			if err != nil {
				continue
			}
			itemKey, err := aead.Decrypt(shareKey, ikBytes, []byte(aead.TagItemKey))
			if err != nil {
				continue
			}
			cBytes, err := base64.StdEncoding.DecodeString(enc.Content)
			if err != nil {
				continue
			}
			plain, err := aead.Decrypt(itemKey, cBytes, []byte(aead.TagItemContent))
			if err != nil {
				continue
			}
			var it pb.Item
			if err := proto.Unmarshal(plain, &it); err != nil {
				continue
			}
			item := itemFromProto(&it)
			item.ShareID = shareID
			item.ItemID = enc.ItemID
			item.Revision = enc.Revision
			item.State = enc.State
			item.CreateTime = enc.CreateTime
			item.ModifyTime = enc.ModifyTime
			out = append(out, *item)
		}
		if r.Items.LastToken == "" || len(r.Items.RevisionsData) == 0 {
			break
		}
		since = r.Items.LastToken
	}
	return out, nil
}

func itemFromProto(it *pb.Item) *Item {
	item := &Item{raw: it, Type: itemTypeName(it)}
	if it.Metadata != nil {
		item.Name = it.Metadata.Name
		item.Note = it.Metadata.Note
	}
	if it.Content == nil || it.Content.Content == nil {
		return item
	}
	switch c := it.Content.Content.(type) {
	case *pb.Content_Login:
		item.Username = c.Login.ItemUsername
		item.Email = c.Login.ItemEmail
		item.Password = c.Login.Password
		item.TOTP = c.Login.TotpUri
		item.URLs = c.Login.Urls
	case *pb.Content_CreditCard:
		item.Holder = c.CreditCard.CardholderName
		item.Number = c.CreditCard.Number
		item.Expiry = c.CreditCard.ExpirationDate
		item.CVV = c.CreditCard.VerificationNumber
		item.PIN = c.CreditCard.Pin
	case *pb.Content_Wifi:
		item.SSID = c.Wifi.Ssid
		item.Password = c.Wifi.Password
	case *pb.Content_SshKey:
		item.PrivateKey = c.SshKey.PrivateKey
		item.PublicKey = c.SshKey.PublicKey
	case *pb.Content_Identity:
		idn := c.Identity
		item.FullName = idn.FullName
		item.FirstName = idn.FirstName
		item.LastName = idn.LastName
		item.Email = idn.Email
		item.Phone = idn.PhoneNumber
		item.Organization = idn.Organization
		item.JobTitle = idn.JobTitle
		item.StreetAddress = idn.StreetAddress
		item.City = idn.City
		item.PostalCode = idn.ZipOrPostalCode
		item.Country = idn.CountryOrRegion
		item.Birthdate = idn.Birthdate
		item.Website = idn.Website
	}
	for _, f := range it.ExtraFields {
		item.Fields = append(item.Fields, extraFieldToItem(f))
	}
	return item
}

func itemTypeName(it *pb.Item) string {
	if it.Content == nil || it.Content.Content == nil {
		return "unknown"
	}
	switch it.Content.Content.(type) {
	case *pb.Content_Login:
		return "login"
	case *pb.Content_Note:
		return "note"
	case *pb.Content_Alias:
		return "alias"
	case *pb.Content_CreditCard:
		return "credit-card"
	case *pb.Content_Identity:
		return "identity"
	case *pb.Content_SshKey:
		return "ssh-key"
	case *pb.Content_Wifi:
		return "wifi"
	case *pb.Content_Custom:
		return "custom"
	}
	return "unknown"
}
