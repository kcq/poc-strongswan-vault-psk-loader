# PoC - Vault PSK Loader for StrongSwan

## PoC Overview

The PoC adds three PSKs to StrongSwan (a static PSK and two PSKs from Vault when it detects those new PSKs).

The PoC service runs until it adds two PSKs it discovers in Vault.

## PSK Loader Service

The service lists the current PSKs (their IDs) whenever it adds a new PSK to verify that StrongSwan knows about it. Note that the PSKs loaded through other interfaces will not be visible (including the PSKs defined in the StrongSwan config files).

## Docker Compose Notes

* Run `dc_build.command` to build the components
* Run `dc_run.command` to run the PoC components (and watch the console output)
* Run `dc_cleanup.command` once you are done (after each PoC execution)

## Add Two PSKs to Vault

Once the PoC containers are up and running it's time to add new PSKs (using Vault UI and API).

Create a PSK through the Vault UI (login with token: `poc-vault-token`). Use the following Create Secret fields:
* Path for this section: `psk/one` (`psk` - path prefix, `one` - key name)
* Version Data (field key value): `name` -> `psk.name.one` , `value` -> `psk.value.one`

Add another PSK using the helper script (`vault_add_psk_two.command`).

## Notes

* Need a recent version of StrongSwan because the ability to load PSKs was not a part of the original version of the Vici interface/plugin.
* The PSK discovery process is pretty basic. A real Vault secret notification implementation is not in scope.



