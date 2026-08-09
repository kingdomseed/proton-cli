package drive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"

	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
	pgphelper "github.com/roman-16/proton-cli/internal/crypto/pgp"
	"github.com/roman-16/proton-cli/internal/progress"
	"github.com/roman-16/proton-cli/internal/proton"
)

type DownloadOptions struct {
	// Label names the transfer for the progress report.
	Label string
	// Progress receives byte counts; nil discards them.
	Progress progress.Sink
}

type revisionBlock struct {
	Index        int
	BareURL      string
	Token        string
	Hash         string
	EncSignature string
}

type revisionThumbnail struct {
	Hash string
}

type revisionMetadata struct {
	ManifestSignature string
	SignatureAddress  string
	SignatureEmail    string
	Thumbnails        []revisionThumbnail
	Blocks            []revisionBlock
}

func (s *Service) Download(ctx context.Context, dc *Context, path string, w io.Writer, opts DownloadOptions) error {
	res, err := s.ResolvePath(ctx, dc, path)
	if err != nil {
		return err
	}
	if res.IsFolder {
		return fmt.Errorf("%s is a folder, not a file", path)
	}
	link, err := s.getLink(ctx, res.ShareID, res.LinkID)
	if err != nil {
		return err
	}
	if err := s.verifyDownloadMetadata(ctx, dc, res, link); err != nil {
		return err
	}
	return s.downloadFile(ctx, res.ShareID, link, res.NodeKR, w, opts)
}

func (s *Service) verifyDownloadMetadata(ctx context.Context, dc *Context, res *Resolved, link *Link) error {
	if link.SignatureEmail == "" {
		return nil
	}
	if verdict := s.verifyCreator(ctx, dc, res, link); verdict != string(pgphelper.Verified) {
		return fmt.Errorf("cannot verify file metadata author %q: %s", link.SignatureEmail, verdict)
	}
	return nil
}

// downloadFile streams and decrypts the active revision of a file link whose
// node key ring (nodeKR) has already been unwrapped.
func (s *Service) downloadFile(ctx context.Context, shareID string, link *Link, nodeKR *pgp.KeyRing, w io.Writer, opts DownloadOptions) error {
	if link.FileProperties == nil {
		return fmt.Errorf("%s: no file properties", link.LinkID)
	}
	kp, err := base64.StdEncoding.DecodeString(link.FileProperties.ContentKeyPacket)
	if err != nil {
		return err
	}
	sk, err := nodeKR.DecryptSessionKey(kp)
	if err != nil {
		return fmt.Errorf("get file session key: %w", err)
	}
	if err := s.verifyContentKeyPacket(ctx, link, nodeKR, sk); err != nil {
		return err
	}

	// Revision blocks are paginated; page through them all so files larger than
	// one page (PageSize blocks) download in full rather than truncating.
	const pageSize = 50
	revID := link.FileProperties.ActiveRevision.ID
	var metadata revisionMetadata
	from := 1
	for {
		var rev struct {
			Revision revisionMetadata
		}
		q := proton.Request{
			Method: "GET",
			Path:   fmt.Sprintf("/drive/shares/%s/files/%s/revisions/%s", shareID, link.LinkID, revID),
		}
		q.Query = make(map[string][]string)
		q.Query.Set("FromBlockIndex", strconv.Itoa(from))
		q.Query.Set("PageSize", strconv.Itoa(pageSize))
		if err := s.C.Decode(ctx, q, &rev); err != nil {
			return err
		}
		if from == 1 {
			metadata.ManifestSignature = rev.Revision.ManifestSignature
			metadata.SignatureAddress = rev.Revision.SignatureAddress
			metadata.SignatureEmail = rev.Revision.SignatureEmail
			metadata.Thumbnails = rev.Revision.Thumbnails
		}
		if len(rev.Revision.Blocks) == 0 {
			break
		}
		metadata.Blocks = append(metadata.Blocks, rev.Revision.Blocks...)
		lastIndex := rev.Revision.Blocks[len(rev.Revision.Blocks)-1].Index
		if lastIndex < from {
			return fmt.Errorf("revision pagination did not advance from block %d", from)
		}
		from = lastIndex + 1
	}
	manifest, hashes, err := revisionManifest(metadata.Thumbnails, metadata.Blocks)
	if err != nil {
		return err
	}
	signatureEmail := metadata.SignatureEmail
	if signatureEmail == "" {
		signatureEmail = metadata.SignatureAddress
	}
	if err := s.verifyManifest(ctx, nodeKR, signatureEmail, manifest, metadata.ManifestSignature); err != nil {
		return err
	}

	prog := progress.Of(opts.Progress)
	prog.Start(link.Size, opts.Label)
	defer prog.Done()

	for i, b := range metadata.Blocks {
		encData, err := downloadBlock(ctx, b.BareURL, b.Token)
		if err != nil {
			return fmt.Errorf("download block %d: %w", i+1, err)
		}
		if err := verifyBlockHash(encData, hashes[i]); err != nil {
			return fmt.Errorf("verify block %d: %w", b.Index, err)
		}
		dec, err := sk.Decrypt(encData)
		if err != nil {
			return fmt.Errorf("decrypt block %d: %w", i+1, err)
		}
		bin := dec.GetBinary()
		if _, err := w.Write(bin); err != nil {
			return err
		}
		prog.Add(int64(len(bin)))
	}
	return nil
}

func (s *Service) verifyContentKeyPacket(ctx context.Context, link *Link, nodeKR *pgp.KeyRing, sk *pgp.SessionKey) error {
	sig := link.FileProperties.ContentKeyPacketSignature
	msg := pgp.NewPlainMessage(sk.Key)
	if pgphelper.VerifyDetachedStatus(nodeKR, msg, sig) == pgphelper.Verified {
		return nil
	}
	// Older Proton clients sometimes signed the content key with an address key.
	if link.SignatureEmail != "" {
		addressKR, err := s.addressKeyRing(ctx, link.SignatureEmail)
		if err == nil && pgphelper.VerifyDetachedStatus(addressKR, msg, sig) == pgphelper.Verified {
			return nil
		}
	}
	return fmt.Errorf("cannot verify file content key signature")
}

func (s *Service) verifyManifest(ctx context.Context, nodeKR *pgp.KeyRing, signatureAddress string, manifest []byte, signature string) error {
	verificationKR := nodeKR
	if signatureAddress != "" {
		kr, err := s.addressKeyRing(ctx, signatureAddress)
		if err != nil {
			return fmt.Errorf("load revision author key %q: %w", signatureAddress, err)
		}
		verificationKR = kr
	}
	if verdict := pgphelper.VerifyDetachedStatus(verificationKR, pgp.NewPlainMessage(manifest), signature); verdict != pgphelper.Verified {
		return fmt.Errorf("cannot verify file manifest signature: %s", verdict)
	}
	return nil
}

func revisionManifest(thumbnails []revisionThumbnail, blocks []revisionBlock) ([]byte, [][]byte, error) {
	manifest := make([]byte, 0, (len(thumbnails)+len(blocks))*sha256.Size)
	for i, thumbnail := range thumbnails {
		hash, err := decodeSHA256(thumbnail.Hash)
		if err != nil {
			return nil, nil, fmt.Errorf("decode thumbnail %d hash: %w", i+1, err)
		}
		manifest = append(manifest, hash...)
	}
	blockHashes := make([][]byte, 0, len(blocks))
	for i, block := range blocks {
		expectedIndex := i + 1
		if block.Index != expectedIndex {
			return nil, nil, fmt.Errorf("revision block index %d, want %d", block.Index, expectedIndex)
		}
		hash, err := decodeSHA256(block.Hash)
		if err != nil {
			return nil, nil, fmt.Errorf("decode block %d hash: %w", block.Index, err)
		}
		blockHashes = append(blockHashes, hash)
		manifest = append(manifest, hash...)
	}
	return manifest, blockHashes, nil
}

func decodeSHA256(encoded string) ([]byte, error) {
	hash, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(hash) != sha256.Size {
		return nil, fmt.Errorf("hash has %d bytes, want %d", len(hash), sha256.Size)
	}
	return hash, nil
}

func verifyBlockHash(encrypted, expected []byte) error {
	actual := sha256.Sum256(encrypted)
	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("encrypted block hash does not match revision manifest")
	}
	return nil
}
