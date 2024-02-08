package ajwks

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Ajwks is an Archive of JWK Sets (JwKS) from an OP
type Ajwks struct {
	Issuer      string
	KidToSetMap map[string]*KidRange
	Sets        []*JwksSave
	Kids        []string
}

func New(issuer string) *Ajwks {
	return &Ajwks{
		Issuer:      issuer,
		KidToSetMap: map[string]*KidRange{},
		Sets:        []*JwksSave{},
		Kids:        []string{},
	}
}

// AddJwksSave adds a new JwksSave to the archive. It assumes saves are added
// in order from old to new
// TODO: Sort the sets
func (a *Ajwks) AddJwksSave(save JwksSave) error {
	if 0 < len(a.Sets) {
		prevSave := a.Sets[len(a.Sets)-1]
		prevSave.NextSave = &save
		save.PrevSave = prevSave
	}
	a.Sets = append(a.Sets, &save)

	for _, jwkKey := range save.JwkKeys {
		if kidRange, ok := a.KidToSetMap[jwkKey.KeyId]; ok {
			if kidRange.FirstSeen > save.TimestampMS {
				kidRange.FirstSeen = save.TimestampMS
			}
			if kidRange.LastSeen < save.TimestampMS {
				kidRange.LastSeen = save.TimestampMS
			}
			kidRange.Saves = append(kidRange.Saves, save)

			if kidRange.JwksKey.JwkKey.X509CertThumbprintS256() != jwkKey.JwkKey.X509CertThumbprintS256() {
				return fmt.Errorf("two different keys have the same kid (collisioN)")
			}
		} else {
			a.KidToSetMap[jwkKey.KeyId] = &KidRange{
				Saves:     []JwksSave{save},
				FirstSeen: save.TimestampMS,
				LastSeen:  save.TimestampMS,
				JwksKey:   jwkKey,
			}
		}
		a.Kids = append(a.Kids, jwkKey.KeyId)
	}
	return nil
}

func (a *Ajwks) Print() {
	fmt.Println(a.Issuer)

	kidSet := map[string]bool{}

	for _, k := range a.Kids {
		if _, ok := kidSet[k]; !ok {
			kidSet[k] = true
		} else {
			continue
		}

		v := a.KidToSetMap[k]

		start := time.UnixMilli(int64(v.FirstSeen))
		stop := time.UnixMilli(int64(v.LastSeen))
		diffDays := int(stop.Sub(start).Hours() / 24)
		fmt.Printf("\t %s (%d)\t%s --> %s,\t%d days\n", k, len(v.Saves), start.UTC().Format("02 Jan 2006"), stop.UTC().Format("02 Jan 2006"), diffDays)
	}
}

// KidRange contains the saves for kid
type KidRange struct {
	Saves     []JwksSave
	FirstSeen uint64
	LastSeen  uint64
	JwksKey   *JwksKey
}

type JwksSave struct {
	Iss string
	// Kid         string
	Epoch       []string
	TimestampMS uint64
	JwkKeys     []*JwksKey
	NextSave    *JwksSave
	PrevSave    *JwksSave
}

type JwksKey struct {
	Issuer      string
	KeyId       string
	Epoch       string
	TimestampMS uint64
	JwkKey      jwk.Key
}
