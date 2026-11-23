# Join declared K3s agents

An agent adds workload capacity to an existing Broil-owned K3s cluster. Broil
joins agents in declaration order after all declared servers are owned and
healthy. A **wave** is up to `agent_wave_size` consecutive agents. Broil joins
each member separately, then checks the whole installed prefix before starting
another wave. This confirms node membership; it does not establish application
service readiness.

## Before joining

Start in the selected Broil project with `BROIL_ENV` set. The first server and
any other declared servers must have completed their joins. Keep the original
member declaration, trusted routes, endpoint, bootstrap assets and owned state.
Each agent needs a completed bootstrap generation, no foreign K3s installation,
and protected `agent-token` references and matching pinned action profiles on
the source and destination. The first server remains the fixed source. See
[host preparation](k3s-bootstrap.md) and [server joining](k3s-server-join.md).

Public [create](k3s-operations.md#create-and-reconcile) prepares the hosts and
sequences the complete declared membership. These individual join commands
require an existing Broil-owned cluster and never adopt an unowned installation.

## Join the next agent

From the project root, replace `lab` and `demo` with your environment and
target. Use the next agent's declared Kubernetes node `name`, rather than its
inventory `machine`. Find it by [inspecting the target declaration](k3s.md#inspect-the-example).
For example, when the agent's machine is `node-4` and its name is `agent-1`:

```sh
BROIL_ENV=lab broil k3s node join demo agent-1 --non-interactive
```

Broil checks the original member set and installed prefix, prepares one
protected source and destination pair, starts the agent service, and confirms
the new node's identity and readiness from the first server. A successful
single join confirms that agent and all earlier installed members. Repeating
the same successful join observes the owned installation without restarting
the agent or preparing new credentials.

To join all remaining declared agents, use:

```sh
BROIL_ENV=lab broil k3s node join-agents demo --non-interactive
```

The batch uses the configured wave width, up to 16. It stops at the first
failed, incomplete or uncertain agent or wave gate. Success confirms the
complete original member set with exact node identities and readiness. An
unavailable later member remains required; Broil does not reduce the target
to the members that happened to respond.

## If a join stops

Use [operation records and recovery](k3s-operations.md) to inspect the
recorded operation and its outcome. `Unknown` means Broil has not established
whether an effect or cleanup completed. `operation resume` observes recorded
participants and effects without replaying a join. Keep the owner and writer
records intact. Resolve an unavailable node, changed identity, foreign member
or uncertain effect before starting another wave. A later batch invocation can
continue a recorded partial wave after its earlier operations have succeeded.
