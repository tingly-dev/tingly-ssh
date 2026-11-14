package mobile

import "github.com/tingly-dev/tingly-ssh/pkg/sshclient"

// SshKeyParser is a thin gomobile facade over sshclient.KeyParser.
type SshKeyParser struct {
	p *sshclient.KeyParser
}

func NewSshKeyParser() *SshKeyParser { return &SshKeyParser{p: sshclient.NewKeyParser()} }

func (p *SshKeyParser) ParseKey(keyContent, passphrase string) (*SshKeyInfo, error) {
	info, err := p.p.ParseKey(keyContent, passphrase)
	if err != nil {
		return nil, err
	}
	return toKeyInfo(info), nil
}

func (p *SshKeyParser) GetSupportedFormats() []string { return p.p.GetSupportedFormats() }

func (p *SshKeyParser) ValidateKey(keyContent string) error { return p.p.ValidateKey(keyContent) }

func (p *SshKeyParser) IsEncrypted(keyContent string) bool { return p.p.IsEncrypted(keyContent) }

func (p *SshKeyParser) DetectKeyFormat(keyContent string) string {
	return p.p.DetectKeyFormat(keyContent)
}

func (p *SshKeyParser) ConvertToPKCS8(keyContent, passphrase string) (string, error) {
	return p.p.ConvertToPKCS8(keyContent, passphrase)
}

func (p *SshKeyParser) GenerateKeyPair(keyType string, bits int, comment string) (*KeyPairResult, error) {
	r, err := p.p.GenerateKeyPair(keyType, bits, comment)
	if err != nil {
		return nil, err
	}
	k := KeyPairResult(*r)
	return &k, nil
}

func (p *SshKeyParser) CalculateFingerprint(publicKey string) (string, error) {
	return p.p.CalculateFingerprint(publicKey)
}

func (p *SshKeyParser) ExtractPublicKey(privateKey, passphrase string) (string, error) {
	return p.p.ExtractPublicKey(privateKey, passphrase)
}
