# K3s configuration example

This project illustrates a cluster target, its remote inventory and backup
destination, and an optional managed registry bound to a client endpoint.
Use it with the [inspection guide](../../k3s.md) to read configuration without
creating infrastructure. For an operational declaration, work through the
[creation prerequisites](../../k3s-create.md#establish-the-target-and-its-prerequisites)
and replace every illustrative input first.

`lab` is the environment and `demo` is the target. Machine `host` becomes node
`server-1`; machine `backup` is outside the cluster. Registry service
`distribution` uses endpoint catalog entry `local`. The `publisher`, `runtime`
and `janitor` principals have distinct publication, node-pull and maintenance
references. The two issuer examples show private-CA and ACME HTTP-01 shapes;
the registry certificate refers to the private CA.

All addresses, nonexistent file paths and the image digest are examples. The
public age recipient is test data; it is not a usable recovery destination for
your private keys. The lifecycle script deliberately refuses execution.
Inspection needs none of these assets to exist. No private key, password or
encrypted secret set is included.
