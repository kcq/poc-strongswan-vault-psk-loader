package main

import (
	"fmt"
	"os"
	"time"

	"github.com/bronze1man/goStrongswanVici"
	"github.com/hashicorp/vault/api"
)

const (
	ssPskKeyType         = "IKE"
	vaultEndpointVarName = "VAULT_ENDPOINT"
	vaultTokenVarName    = "VAULT_TOKEN"
	pskRecordsMetaPrefix = "secret/metadata/psk"
	pskRecordsDataPrefix = "secret/data/psk"
	dataFieldData        = "data"
	dataFieldKeyName     = "name"
	dataFieldKeyValue    = "value"
	metaFieldKeys        = "keys"
	metaFieldKeyUpdated  = "updated_time"
	metaFieldKeyVersions = "versions"
)

type pskInfo struct {
	id       string
	name     string
	value    string
	updated  string
	versions int
}

func main() {
	fmt.Println("StrongSwan/Vault PSK PoC...")
	time.Sleep(7 * time.Second)

	vaultEndpoint := os.Getenv(vaultEndpointVarName)
	vaultToken := os.Getenv(vaultTokenVarName)
	
	vaultPSKs := map[string]*pskInfo{}

	vault, err := api.NewClient(&api.Config{
		Address: vaultEndpoint,
	})
	if err != nil {
		panic(err)
	}

	vault.SetToken(vaultToken)

	ss, err := goStrongswanVici.NewClientConnFromDefaultSocket()
	if err != nil {
		panic(err)
	}
	defer ss.Close()

	showVersion(ss)

	fmt.Println("List existing PSKs...")
	showLoadedPSKs(ss)

	fmt.Println("Adding a static PSK...")
	err = addPsk(ss, "STATIC:PSK.KEY", "dummy.static.psk.value")
	if err != nil {
		panic(err)
	}

	showLoadedPSKs(ss)

	fmt.Println("Load PSKs from Vault...")
	for pskCount := 0; pskCount < 2; {
	Loop:
		for {
			select {
			case <-time.After(5 * time.Second):
				if pskList := getNewVaultPSKs(vaultPSKs, vault); len(pskList) > 0 {
					for _, psk := range pskList {
						fmt.Printf("Adding new PSK: %+v\n", psk)
						if err := addPskInfo(ss, psk); err != nil {
							panic(err)
						}
					}

					addVaultPSKs(vaultPSKs, pskList)
					showLoadedPSKs(ss)

					pskCount += len(pskList)
					break Loop
				} else {
					fmt.Println("No new PSKs to add...")
				}
			}
		}
	}

	fmt.Println("StrongSwan/Vault PSK PoC: done!")
}

func listVaultRecordIDs(vault *api.Client) []string {
	keyList, err := vault.Logical().List(pskRecordsMetaPrefix)
	if err != nil {
		panic(err)
	}

	if keyList == nil {
		fmt.Println("No keys...")
		return nil
	}

	if _, exists := keyList.Data[metaFieldKeys]; !exists {
		panic(fmt.Errorf("%v - unexpected data format (missing keys)\n", pskRecordsMetaPrefix))
	}

	list, ok := keyList.Data[metaFieldKeys].([]interface{})
	if !ok {
		panic(fmt.Errorf("%v - unexpected data format (keys is not a list)\n", pskRecordsMetaPrefix))
	}

	if len(list) == 0 {
		fmt.Println("No keys (empty list)...")
		return nil
	}

	var keys []string
	for _, item := range list {
		if key, ok := item.(string); ok {
			keys = append(keys, key)
		} else {
			fmt.Println("Unexpected key field type (ignoring)...")
		}
	}

	return keys
}

func getVaultRecord(vault *api.Client, id string) *pskInfo {
	dataKey := fmt.Sprintf("%s/%s", pskRecordsDataPrefix, id)
	data, err := vault.Logical().Read(dataKey)
	if err != nil {
		panic(err)
	}

	if data == nil || data.Data == nil {
		panic(fmt.Errorf("%s - no record or missing record data\n", dataKey))
	}

	if _, exists := data.Data[dataFieldData]; !exists {
		panic(fmt.Errorf("%v - unexpected data format (missing data section)\n", dataKey))
	}

	fields, ok := data.Data[dataFieldData].(map[string]interface{})
	if !ok {
		panic(fmt.Errorf("%s - bad record data (data fields) -> %#v\n",
			dataKey, data.Data[dataFieldData]))
	}

	metaKey := fmt.Sprintf("%s/%s", pskRecordsMetaPrefix, id)
	meta, err := vault.Logical().Read(metaKey)
	if err != nil {
		panic(err)
	}

	if meta == nil || meta.Data == nil {
		panic(fmt.Errorf("%s - record has no metadata\n", metaKey))
	}

	versionCount := -1
	if _, ok := meta.Data[metaFieldKeyVersions]; ok {
		if vmap, ok := meta.Data[metaFieldKeyVersions].(map[string]interface{}); ok {
			versionCount = len(vmap)
		}
	} else {
		fmt.Println("no versions info in metadata")
	}

	if _, exists := meta.Data[metaFieldKeyUpdated]; !exists {
		panic(fmt.Errorf("%v - unexpected data format (missing field: %v)\n", metaKey, metaFieldKeyUpdated))
	}

	updated, ok := meta.Data[metaFieldKeyUpdated].(string)
	if !ok {
		panic(fmt.Errorf("%s - bad record metadata (updated) -> %#v\n",
			metaKey, meta.Data[metaFieldKeyUpdated]))
	}

	name, ok := fields[dataFieldKeyName].(string)
	if !ok {
		panic(fmt.Errorf("%s - bad record data field (name) -> %#v\n",
			dataKey, fields[dataFieldKeyName]))
	}

	value, ok := fields[dataFieldKeyValue].(string)
	if !ok {
		panic(fmt.Errorf("%s - bad record data field (value) -> %#v\n",
			dataKey, fields[dataFieldKeyValue]))
	}

	psk := pskInfo{
		id:       id,
		name:     name,
		value:    value,
		updated:  updated,
		versions: versionCount,
	}

	return &psk
}

func getNewVaultPSKs(pskSet map[string]*pskInfo, vault *api.Client) []*pskInfo {
	var pskList []*pskInfo

	idList := listVaultRecordIDs(vault)
	for _, id := range idList {
		vaultPSK := getVaultRecord(vault, id)
		if vaultPSK == nil {
			fmt.Println("Failed to get PSK - %s (skipping record)")
			continue
		}

		if psk, exists := pskSet[id]; exists {
			fmt.Printf("Known PSK - %s\n", id)
			if psk.updated != vaultPSK.updated {
				fmt.Printf("Updated PSK - %s (ignoring update)\n", id)
			}
		} else {
			fmt.Printf("New PSK - %s\n", id)
			pskList = append(pskList, vaultPSK)
		}
	}

	return pskList
}

func addVaultPSKs(pskSet map[string]*pskInfo, pskList []*pskInfo) {
	for _, psk := range pskList {
		pskSet[psk.id] = psk
	}
}

func addPskInfo(ss *goStrongswanVici.ClientConn, psk *pskInfo) error {
	return addPsk(ss, fmt.Sprintf("%s:%s", psk.id, psk.name), psk.value)
}

func addPsk(ss *goStrongswanVici.ClientConn, id string, value string) error {
	//not setting 'Owners' in this PoC, but still need it...
	data := &goStrongswanVici.Key{
		ID:     id,
		Typ:    ssPskKeyType,
		Data:   value,
		Owners: []string{""},
	}

	return ss.LoadShared(data)
}

func showLoadedPSKs(ss *goStrongswanVici.ClientConn) {
	idList, err := ss.GetShared()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Current PSK IDs (%v):\n", len(idList))
	if len(idList) == 0 {
		fmt.Println("<empty>")
	}
	for _, id := range idList {
		fmt.Println(id)
	}
}

func showVersion(ss *goStrongswanVici.ClientConn) {
	version, err := ss.Version()
	if err != nil {
		panic(err)
	}

	fmt.Printf("StrongSwan Version: %+v\n", version)
}
