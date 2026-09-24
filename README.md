# TCP Port Scanner

A multithreaded TCP port scanner written in C# (.NET 8).

Given a host and a port range, it attempts a TCP connection to each port
and classifies the result as **OPEN**, **CLOSED**, or **FILTERED**.
Results are printed to the console and appended to `portscan.log`.

---

## What "open", "closed", and "filtered" actually mean

A TCP port scan is just a bunch of connection attempts. Each one has
three possible outcomes at the network level:

| Result       | What happened on the wire                                     | What it means in practice |
|--------------|----------------------------------------------------------------|---------------------------|
| **OPEN**     | SYN → SYN-ACK → ACK (full handshake)                           | A service is listening on that port |
| **CLOSED**   | SYN → RST (server refuses immediately)                         | Nothing is listening, but the host is reachable |
| **FILTERED** | SYN → (silence). No reply within the timeout.                  | A firewall is dropping the packet, or the host is down |

This distinction is the entire point of a port scanner. A port that
replies "closed" is a *different* finding from a port that silently
swallows your packet.

---

## How it works

1. **Resolve** the hostname to an IPv4 address using `Dns.GetHostAddressesAsync`.
2. **For each port** in the range, spin up a `Task` that calls
   `TcpClient.ConnectAsync(ip, port, cancellationToken)`.
3. **Bound concurrency** with a `SemaphoreSlim` so we never have more
   than N connections in flight at once (default 100).
4. **Per-port timeout** via `CancellationTokenSource(timeoutMs)`.
   If the token fires, the port is classified as FILTERED.
5. **Collect results** in a `ConcurrentBag<ScanResult>` (thread-safe).
6. **Log** every result to the console and to `portscan.log` under a
   `lock` so the file writes don't interleave.

---

## Concurrency model

The naive approach — `Parallel.For` or spawning one thread per port —
falls over quickly:

- 65,535 threads would exhaust the OS thread stack.
- Each thread would be blocked on I/O anyway, wasting memory.

Instead, this project uses the **async/await + bounded parallelism**
pattern:

```csharp
using var semaphore = new SemaphoreSlim(threads);

for (int port = startPort; port <= endPort; port++)
{
    int p = port;
    await semaphore.WaitAsync();
    tasks.Add(Task.Run(async () =>
    {
        try   { /* probe port p */ }
        finally { semaphore.Release(); }
    }));
}
