here="$(dirname "$BASH_SOURCE")"
cd $here
docker-compose down
docker volume rm psk_loader_xcharondata
