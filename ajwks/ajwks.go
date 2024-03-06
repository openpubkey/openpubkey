package ajwks

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"io"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Ajwks is an Archive of JWK Sets (JwKS) from an OP
type Ajwks struct {
	Issuer      string               `json:"iss"`
	KidToSetMap map[string]*KidRange `json:"kidranges,omitempty"`
	Sets        []*JwksSave          `json:"saves,omitempty"`
	Kids        []string             `json:"kids,omitempty"`
}

func New(issuer string) *Ajwks {
	return &Ajwks{
		Issuer:      issuer,
		KidToSetMap: map[string]*KidRange{},
		Sets:        []*JwksSave{},
		Kids:        []string{},
	}
}

func NewFromFile(fpath string) (*Ajwks, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	j, err := io.ReadAll(io.Reader(f))
	if err != nil {
		return nil, err
	}

	aFromJson := &Ajwks{}
	if err := json.Unmarshal(j, aFromJson); err != nil {
		return nil, err
	}

	// We want to cleanly rebuild/reindex the archive from scratch
	a := &Ajwks{
		Issuer:      aFromJson.Issuer,
		KidToSetMap: map[string]*KidRange{},
		Sets:        []*JwksSave{},
		Kids:        []string{},
	}
	for _, v := range aFromJson.Sets {
		a.AddJwksSave(*v)
	}
	return a, nil
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
		if kidRange, ok := a.KidToSetMap[jwkKey.KeyID]; ok {
			if kidRange.FirstSeen > save.CreateTime {
				kidRange.FirstSeen = save.CreateTime
			}
			if kidRange.LastSeen < save.CreateTime {
				kidRange.LastSeen = save.CreateTime
			}
			kidRange.Saves = append(kidRange.Saves, save)

			if kidRange.JwksKey.JwkKey.X509CertThumbprintS256() != jwkKey.JwkKey.X509CertThumbprintS256() {
				return fmt.Errorf("two different keys have the same kid (collisioN)")
			}
		} else {
			a.KidToSetMap[jwkKey.KeyID] = &KidRange{
				Saves:     []JwksSave{save},
				FirstSeen: save.CreateTime,
				LastSeen:  save.CreateTime,
				JwksKey:   jwkKey,
			}
		}
		a.Kids = append(a.Kids, jwkKey.KeyID)
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

func (a *Ajwks) GetSaves() ([]byte, error) {
	return json.MarshalIndent(a.Sets, "", "    ")
}

func (a *Ajwks) MarshalJSON() ([]byte, error) {
	outputAJwks := Ajwks{
		Issuer: a.Issuer,
		Sets:   a.Sets,
		// Nil out the values we don't want to save
		KidToSetMap: nil,
		Kids:        nil,
	}
	return json.MarshalIndent(outputAJwks, "", "    ")
}

func (a *Ajwks) SaveToFile(fpath string) error {
	j, err := a.MarshalJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(fpath, j, 0644)
}

// KidRange contains the saves for kid
type KidRange struct {
	Saves     []JwksSave
	FirstSeen uint64
	LastSeen  uint64
	JwksKey   *JwksKey
}

type JwksSave struct {
	Issuer string   `json:"iss"`
	Epoch  []string `json:"epochs,omitempty"`
	// This is unixtime in milliseconds of the JWKS provided by the source we are downloading from. Not all sources have timestamps.
	CreateTime uint64 `json:"create-time,omitempty"`
	// This is unixtime in milliseconds when we downloaded this JWKS from the source JWKS. When downloading directly from the JWKS the DownloadTime is also the CreateTime.
	DownloadTime uint64     `json:"download-time,omitempty"`
	JwkKeys      []*JwksKey `json:"jwks,omitempty"`
	NextSave     *JwksSave  `json:"next,omitempty"`
	PrevSave     *JwksSave  `json:"prev,omitempty"`
	// The source is either the original JWKS or a secondary archive such as the SUI blockchain
	Source string `json:"source,omitempty"`
}

func (s *JwksSave) MarshalJSON() ([]byte, error) {
	outputJwksSave := JwksSave{
		Issuer:       s.Issuer,
		Epoch:        s.Epoch,
		CreateTime:   s.CreateTime,
		DownloadTime: s.DownloadTime,
		JwkKeys:      s.JwkKeys,
		NextSave:     nil,
		PrevSave:     nil,
		Source:       s.Source,
	}
	return json.Marshal(outputJwksSave)
}

type JwksKey struct {
	Issuer      string  `json:"iss"`
	KeyID       string  `json:"kid"`
	Epoch       string  `json:"epoch"`
	TimestampMS uint64  `json:"timestampMS"`
	JwkKey      jwk.Key `json:"-"`
}

func (k *JwksKey) MarshalJSON() ([]byte, error) {
	type Alias JwksKey
	aux := &struct {
		JwkKey jwk.Key `json:"jwk"`
		*Alias
	}{
		Alias: (*Alias)(k),
	}

	aux.JwkKey = k.JwkKey
	return json.Marshal(aux)
}

func (k *JwksKey) UnmarshalJSON(data []byte) error {
	type Alias JwksKey
	aux := &struct {
		JwkKey map[string]string `json:"jwk"`
		*Alias
	}{
		Alias: (*Alias)(k),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	// Deserializing from Json to a map and then back to JSON and then
	// feeding the JSON to jwk.ParseKey seems chunky. There has to be
	// a better way.
	jwkJson, err := json.Marshal(aux.JwkKey)
	if err != nil {
		return err
	}
	key, err := jwk.ParseKey(jwkJson)
	k.JwkKey = key

	return err
}
