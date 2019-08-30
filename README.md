These are some of the more useful SaltStack (https://docs.saltstack.com/en/latest/) modules I've written.

`_modules/tls_inject.py`

`_modules/file_inject.py`

`_states/file_inject.py`

These execution and state modules introduce new functions into existing virtual modules.

The earliest of these were written out of spite. The upstream `archive` function seemed to break with every release.

Next came the TLS-related functions, for managing files containing PEM-formatted certificates, private keys, and Diffie-Hellman parameters. Self-signed certificates can be generated, or existing certificates can be stored in Pillar as variables. The functions include verification routines, allowing certificates to be regenerated as they near expiration.

Finally, there's a function that allows defining file states in Pillar, instead of the state tree. Combined with PillarStack below, this was a powerful way to dynamically generate and manage configurations. This concept went through many incarnations over the years, some quite insane, but this one seemed pretty reasonable.

`_extmods/pillar/stack.py`

This is a fork of the PillarStack (https://github.com/bbinet/pillarstack) pillar module.

Notable changes:
* The `stack` variable is initialized to `pillar`, the result of any previously executed pillar modules, instead of `{}` (empty). This avoids stack data files from needing to check both locations. Every. Single. Time.
* The upstream version is strictly limited to a `jinja|yaml` rendering pipeline. My version allows an arbitrary pipeline to be defined in the shebang at the top of each file. This was mostly used for simplifying `gpg` usage. Before this change, I was having to store encrypted variables in an earlier-loaded pillar module, requiring awkward design decisions.

