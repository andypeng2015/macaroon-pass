package macaroon_pass

import (
	"encoding/base64"
	"testing"
)

//func randomBytes(n int) []byte {
//	b := make([]byte, n)
//	_, err := rand.Read(b)
//	if err != nil {
//		panic(err)
//	}
//	return b
//}

func BenchmarkNew(b *testing.B) {
	rootKey := randomBytes(24)
	id := []byte(base64.StdEncoding.EncodeToString(randomBytes(100)))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		m := MustNew(id, loc, LatestVersion)
		signer, _ := NewHmacSha256Signer(MakeKey(rootKey))
		m.Sign(&signer)
	}
}

func BenchmarkAddCaveat(b *testing.B) {
	rootKey := randomBytes(24)
	id := []byte(base64.StdEncoding.EncodeToString(randomBytes(100)))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		b.StopTimer()
		m := MustNew(id, loc, LatestVersion)
		b.StartTimer()
		m.AddFirstPartyCaveat([]byte("some caveat stuff"))
		signer, _ := NewHmacSha256Signer(MakeKey(rootKey))
		m.Sign(&signer)
	}
}

//func benchmarkVerify(b *testing.B, mspecs []macaroonSpec) {
//	rootKey, macaroons := makeMacaroons(mspecs)
//	check := func(string) error {
//		return nil
//	}
//	b.ResetTimer()
//	for i := b.N - 1; i >= 0; i-- {
//		err := macaroons[0].Verify(rootKey, check, macaroons[1:])
//		if err != nil {
//			b.Fatalf("verification failed: %v", err)
//		}
//	}
//}

//func BenchmarkVerifyLarge(b *testing.B) {
//	benchmarkVerify(b, multilevelThirdPartyCaveatMacaroons)
//}
//
//func BenchmarkVerifySmall(b *testing.B) {
//	benchmarkVerify(b, []macaroonSpec{{
//		rootKey: "root-key",
//		id:      "root-id",
//		caveats: []caveat{{
//			condition: "wonderful",
//		}},
//	}})
//}

func BenchmarkMarshalJSON(b *testing.B) {
	rootKey := randomBytes(24)
	id := []byte(base64.StdEncoding.EncodeToString(randomBytes(100)))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	m := marshaller{MustNew(id, loc, LatestVersion)}
	signer, _ := NewHmacSha256Signer(MakeKey(rootKey))
	m.Sign(&signer)
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		_, err := m.MarshalJSON()
		if err != nil {
			b.Fatalf("cannot marshal JSON: %v", err)
		}
	}
}

func MustNew(id []byte, loc string, vers Version) *Macaroon {
	m, err := New(id, loc, vers)
	if err != nil {
		panic(err)
	}
	//m.Sign(MakeKey(rootKey), HmacSha256Signer)
	return m
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	rootKey := randomBytes(24)
	id := []byte(base64.StdEncoding.EncodeToString(randomBytes(100)))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	m := marshaller{MustNew(id, loc, LatestVersion)}
	signer, _ := NewHmacSha256Signer(MakeKey(rootKey))
	m.Sign(&signer)
	data, err := m.MarshalJSON()
	if err != nil {
		b.Fatalf("cannot marshal JSON: %v", err)
	}
	for i := b.N - 1; i >= 0; i-- {
		m := marshaller{&Macaroon{}}
		err := m.UnmarshalJSON(data)
		if err != nil {
			b.Fatalf("cannot unmarshal JSON: %v", err)
		}
	}
}
