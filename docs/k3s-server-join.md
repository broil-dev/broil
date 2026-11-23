# Join the next K3s server

An additional server can increase an existing Broil-owned embedded-etcd
cluster's voter count. Broil joins one declared server at a time. After the
second server joins, the three-server target is still incomplete; join the
third before treating the declared server membership as complete.
The server path does not join agents or establish application-service readiness.
For agents after server completion, see [join declared agents](k3s-agent-join.md).

## Before joining

Start in the selected Broil project with `BROIL_ENV` set to the environment.
The target must declare exactly three servers in their intended join order.
The first server must already be installed, published and owned by Broil, with
working administrator access. Every declared member must retain its original
machine, node, address, configuration, owner and trusted SSH route. The selected
server needs a completed bootstrap asset generation and no foreign K3s
installation. Configure the protected server-join credential references and
the matching pinned action profile on every member. See
[host preparation](k3s-bootstrap.md) for these prerequisites.

Public [create](k3s-operations.md#create-and-reconcile) prepares the hosts and
sequences the complete declared membership. These individual join commands
require an existing Broil-owned cluster and never adopt an unowned installation.

## Join one server

From the project root, replace `lab` and `demo` with your environment and target.
Use the next server's declared Kubernetes node name (`name` in the target's
`members`), which you can find by [inspecting the target declaration](k3s.md#inspect-the-example).
For example, if its `machine` is `node-2` and its `name` is `server-2`, enter
`server-2`:

```sh
BROIL_ENV=lab broil k3s node join demo server-2 --non-interactive
```

Broil checks the complete original member selection, every installed server's
live etcd membership and health, and the destination's absence before it
acquires writers. One operation prepares a fresh source/destination credential
pair, activates and starts the destination, verifies the new voter from all
installed servers, then publishes its owned node identity and settles writers.
A successful command confirms that selected server's join. It does not claim
that all declared servers or services are ready.

For a three-server target, run the same command with the third server only
after the second join succeeds:

```sh
BROIL_ENV=lab broil k3s node join demo server-3 --non-interactive
```

Broil refuses an out-of-order server. Repeating a successful join observes
the existing installation and current voter health; it does not prepare new
credentials, restart K3s or publish the member again.

## If the operation is incomplete

Use [operation records and recovery](k3s-operations.md) to find the operation
ID and inspect its outcome. `Unknown` can mean a remote effect or cleanup has
not been established. `operation resume` observes the original participants,
resources and receipts without replaying the join or retrying membership.
Keep the recorded owner and writer files intact. An unavailable voter, learner,
unexpected etcd member, changed configuration or uncertain effect requires
investigation before another join.
