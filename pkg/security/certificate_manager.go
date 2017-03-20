// Copyright 2017 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// Author: Marc Berhault (marc@cockroachlabs.com)

package security

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/cockroachdb/cockroach/pkg/util/log"
	"github.com/pkg/errors"
)

//go:generate stringer -type=pemType

type CertificateManager struct {
	certDir string
}

type pemType uint32

const (
	_ pemType = iota
	caCertificate
	nodeCertificate
	clientCertificate
	privateKey

	// Maximum allowable permissions.
	maxDirectoryPermissions   os.FileMode = 0700
	maxKeyPermissions         os.FileMode = 0700
	maxCertificatePermissions os.FileMode = 0755
)

// pemFile describes a parsed pem-encoded file.
type pemFile struct {
	filename string
	fileType pemType

	// tls.Certificate contains a certificate chain, a private key, or both.
	certificate tls.Certificate
}

func exceedsPermissions(objectMode, allowedMode os.FileMode) bool {
	mask := os.FileMode(0777) ^ allowedMode
	return mask&objectMode != 0
}

func (c *CertificateManager) validateCertDir() error {
	info, err := os.Stat(c.certDir)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return errors.Errorf("%s is not a directory", c.certDir)
	}

	if perms := info.Mode().Perm(); exceedsPermissions(perms, maxDirectoryPermissions) {
		return errors.Errorf("cert directory %s has permissions %s, cannot be more than %s",
			c.certDir, perms, maxDirectoryPermissions)
	}

	return nil
}

func (c *CertificateManager) Reload() error {
	if err := c.validateCertDir(); err != nil {
		return err
	}

	fileInfos, err := ioutil.ReadDir(c.certDir)
	if err != nil {
		return err
	}

	for _, info := range fileInfos {
		fullPath := path.Join(c.certDir, info.Name())
		if info.IsDir() {
			if log.V(3) {
				log.Infof(context.Background(), "skipping sub-directory %s", fullPath)
			}
			continue
		}

		pemFile, err := parsePEMFile(fullPath)
		if err != nil {
			// TODO(marc): do we expect invalid files frequently? If so, put behind log.V.
			log.Warningf(context.Background(), "invalid PEM file %s: %v", fullPath, err)
			continue
		}

		log.Infof(context.Background(), "found %+v", pemFile)
	}

	return nil
}

func NewCertificateManager(certDirectory string) *CertificateManager {
	return &CertificateManager{certDir: certDirectory}
}

// parsePEMFile takes the full path to a certificate or key file.
// Do not include the file path in errors, this is done by the caller.
func parsePEMFile(fullPath string) (*pemFile, error) {
	pf := &pemFile{
		filename: fullPath,
	}

	// We use LStat to avoid following symlinks.
	info, err := os.Lstat(fullPath)
	if err != nil {
		return nil, err
	}

	fileMode := info.Mode()
	if !fileMode.IsRegular() {
		return nil, errors.New("not a regular file")
	}

	pemBlock, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	// Decode all PEM blocks into a tls.Certificate.
	cert, err := certificateFromPEMBlocks(pemBlock)
	if err != nil {
		return nil, err
	}

	filePerm := fileMode.Perm()
	if len(cert.Certificate) > 0 {
		if exceedsPermissions(filePerm, maxCertificatePermissions) {
			return nil, errors.Errorf("certificate file has permissions %s, cannot be more than %s",
				filePerm, maxCertificatePermissions)
		}

		pf.fileType = caCertificate
		pf.certificate = cert
	} else if cert.PrivateKey != nil {
		if exceedsPermissions(filePerm, maxKeyPermissions) {
			return nil, errors.Errorf("private key file has permissions %s, cannot be more than %s",
				filePerm, maxKeyPermissions)
		}

		pf.fileType = privateKey
		pf.certificate = cert
	}

	return pf, nil
}

// certificateFromPEMBlocks takes file contents and attempts to decode all PEM blocks.
// Only two cases are valid:
// - one or more CERTIFICATE blocks (stored in cert.Certificate)
// - exactly one private key (stored in cert.PrivateKey)
// The logic should not stray too much from https://golang.org/src/crypto/tls/tls.go?s=5407:5474#L168
// to avoid surprises.
func certificateFromPEMBlocks(contents []byte) (tls.Certificate, error) {
	seenTypes := make(map[string]struct{})
	pemBlocks := make([]*pem.Block, 0, 0)

	// First load up all blocks and types.
	for {
		var block *pem.Block
		block, contents = pem.Decode(contents)
		if block == nil {
			break
		}
		pemBlocks = append(pemBlocks, block)
		seenTypes[block.Type] = struct{}{}
	}

	var cert tls.Certificate

	if len(pemBlocks) == 0 || len(seenTypes) == 0 {
		// Empty file, or non-pem data.
		return cert, errors.New("no PEM blocks found")
	}

	if len(seenTypes) > 1 {
		// Blocks of mixed types are not allowed.
		return cert, errors.Errorf("multiple PEM block types found: %v", seenTypes)
	}

	// Now that all types are the same, use type from the first block.
	blockType := pemBlocks[0].Type
	if blockType == "CERTIFICATE" {
		// Copy the entire certificate chain.
		for _, b := range pemBlocks {
			cert.Certificate = append(cert.Certificate, b.Bytes)
		}
		return cert, nil
	} else if blockType == "PRIVATE KEY" || strings.HasSuffix(blockType, " PRIVATE KEY") {
		if len(pemBlocks) > 1 {
			return cert, errors.Errorf("only one PRIVATE KEY block supported, found %d", len(pemBlocks))
		}
		key, err := parsePrivateKey(pemBlocks[0].Bytes)
		if err != nil {
			return cert, err
		}
		cert.PrivateKey = key
		return cert, nil
	}

	return cert, errors.Errorf("unsupported block type: %s", blockType)
}

// This is lifted directly from https://golang.org/src/crypto/tls/tls.go?s=5407:5474#L168
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
