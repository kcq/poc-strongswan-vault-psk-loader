here="$(dirname "$BASH_SOURCE")"
cd $here
curl --header "Authorization: Bearer poc-vault-token" -X POST http://127.0.0.1:8200/v1/secret/data/psk/two -d '{"data":{"name":"psk.name.two","value":"psk.value.two"}}'
