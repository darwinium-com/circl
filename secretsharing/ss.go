// Package secretsharing provides methods to split secrets into shares.
//
// Let n be the number of parties, and t the number of corrupted parties such
// that 0 <= t < n. A (t,n) secret sharing allows to split a secret into n
// shares, such that the secret can be recovered from any subset of t+1 shares.
//
// The NewShamirSecretSharing function creates a Shamir secret sharing [1],
// which relies on Lagrange polynomial interpolation.
//
// The NewFeldmanSecretSharing function creates a Feldman secret sharing [2],
// which extends Shamir's by allowing to verify that a share is part of a
// committed secret.
//
// In this implementation, secret sharing is defined over the scalar field of
// a prime order group.
//
// References
//
//	[1] https://dl.acm.org/doi/10.1145/359168.359176
//	[2] https://ieeexplore.ieee.org/document/4568297
package secretsharing

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/math/polynomial"
)

// Share represents a share of a secret.
type Share struct {
	ID    uint64       // ID uniquely identifies a share in a secret sharing instance.
	Value group.Scalar // Value stores the share generated from a secret sharing instance.
}

type SecretSharing struct {
	g    group.Group
	t, n uint
}

// NewShamirSecretSharing implements a (t,n) Shamir's secret sharing.
// A (t,n) secret sharing allows to split a secret into n shares, such that the
// secret can be only recovered from any subset of t+1 shares. Returns an error
// if 0 <= t < n does not hold.
func NewShamirSecretSharing(g group.Group, t, n uint) (SecretSharing, error) {
	if t >= n {
		return SecretSharing{}, errors.New("secretsharing: bad parameters")
	}
	return SecretSharing{g: g, t: t, n: n}, nil
}

// Params returns the t and n parameters of the secret sharing.
func (s SecretSharing) Params() (t, n uint) { return s.t, s.n }

func (s SecretSharing) polyFromSecret(rnd io.Reader, secret group.Scalar) (p polynomial.Polynomial) {
	c := make([]group.Scalar, s.t+1)
	for i := 1; i < len(c); i++ {
		c[i] = s.g.RandomScalar(rnd)
	}
	c[0] = secret.Copy()
	return polynomial.New(c)
}

func (s SecretSharing) generateShares(poly polynomial.Polynomial) []Share {
	shares := make([]Share, s.n)
	x := s.g.NewScalar()
	for i := range shares {
		id := i + 1
		x.SetUint64(uint64(id))
		shares[i].ID = uint64(id)
		shares[i].Value = poly.Evaluate(x)
	}

	return shares
}

// Shard splits the secret into n shares.
func (s SecretSharing) Shard(rnd io.Reader, secret group.Scalar) []Share {
	return s.generateShares(s.polyFromSecret(rnd, secret))
}

// Recover returns the secret provided more than t shares are given. Returns an
// error if the number of shares is not above the threshold or goes beyond the
// maximum number of shares.
func (s SecretSharing) Recover(shares []Share) (group.Scalar, error) {
	if l := len(shares); l <= int(s.t) {
		return nil, fmt.Errorf("secretsharing: does not reach the threshold %v with %v shares", s.t, l)
	} else if l > int(s.n) {
		return nil, fmt.Errorf("secretsharing: %v shares above max number of shares %v", l, s.n)
	}

	x := make([]group.Scalar, s.t+1)
	px := make([]group.Scalar, s.t+1)
	for i := range shares[:s.t+1] {
		x[i] = s.g.NewScalar().SetUint64(shares[i].ID)
		px[i] = shares[i].Value
	}

	l := polynomial.NewLagrangePolynomial(x, px)
	zero := s.g.NewScalar()

	return l.Evaluate(zero), nil
}

type SharesCommitment = []group.Element

type VerifiableSecretSharing struct{ s SecretSharing }

// NewFeldmanSecretSharing implements a (t,n) Feldman's verifiable secret
// sharing. A (t,n) secret sharing allows to split a secret into n shares, such
// that the secret can be only recovered from any subset of t+1 shares. This
// method is verifiable because once the shares and the secret are committed
// during sharding, one can later verify whether the share was generated
// honestly. Returns an error if 0 < t <= n does not hold.
func NewFeldmanSecretSharing(g group.Group, t, n uint) (VerifiableSecretSharing, error) {
	s, err := NewShamirSecretSharing(g, t, n)
	return VerifiableSecretSharing{s}, err
}

// Params returns the t and n parameters of the secret sharing.
func (v VerifiableSecretSharing) Params() (t, n uint) { return v.s.Params() }

// Shard splits the secret into n shares, and also returns a commitment to both
// the secret and the shares. The ShareCommitment must be sent to each party
// so each party can verify its share is correct. Sharding a secret more
// than once produces ShareCommitments with the same first entry.
func (v VerifiableSecretSharing) Shard(rnd io.Reader, secret group.Scalar) ([]Share, SharesCommitment) {
	poly := v.s.polyFromSecret(rnd, secret)
	shares := v.s.generateShares(poly)
	shareComs := make(SharesCommitment, poly.Degree()+1)
	for i := range shareComs {
		shareComs[i] = v.s.g.NewElement().MulGen(poly.Coefficient(uint(i)))
	}

	return shares, shareComs
}

// Verify returns true if a share was produced by sharding a secret. It uses
// the share commitments generated by the Shard function to verify this
// property.
func (v VerifiableSecretSharing) Verify(s Share, c SharesCommitment) bool {
	if len(c) != int(v.s.t+1) {
		return false
	}

	lc := len(c) - 1
	sum := v.s.g.NewElement().Set(c[lc])
	x := v.s.g.NewScalar()
	for i := lc - 1; i >= 0; i-- {
		x.SetUint64(s.ID)
		sum.Mul(sum, x)
		sum.Add(sum, c[i])
	}
	polI := v.s.g.NewElement().MulGen(s.Value)
	return polI.IsEqual(sum)
}

// Recover returns the secret provided more than t shares are given. Returns an
// error if the number of shares is not above the threshold (t) or is larger
// than the maximum number of shares (n).
func (v VerifiableSecretSharing) Recover(shares []Share) (group.Scalar, error) {
	return v.s.Recover(shares)
}
