# MCP list caching and tool poisoning

> Источник (сконвертировано из HTML): MCP list caching and tool poisoning.html

The [2026-07-28 Model Context Protocol specification](https://blog.modelcontextprotocol.io/posts/2026-07-28/) is out. One interesting addition for application security:

**List results are cacheable**

Responses from `tools/list`, `prompts/list`, `resources/list`, and `resources/read` now carry `ttlMs` and `cacheScope` ([SEP-2549](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2549)). This allows clients to determine the best caching strategy for responses and reduce unnecessary re-fetching.


On paper, cache hints help performance. They also give clients a way to slow down a known MCP attack pattern, if the client treats catalog changes as a security event and not only as a cache miss.

## The problem: approve once, change later

[Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) described **tool poisoning**. In a tool poisoning attack, an MCP server puts harmful instructions inside a tool description. The model reads the full description. The user often sees only a short name in the UI.

A harder case is when the description changes after approval. The user connects an MCP server and approves a tool that looks ordinary, such as `add`, `search`, or `list_files`. The client then treats that tool list as trusted. Later, the same server returns a new `tools/list` response. The tool name is unchanged, but the description now includes hidden instructions, extra arguments used to move data out, or text that tells the model to change how a different trusted tool behaves. The model follows the new text. The UI can still show the friendly name the user already approved.

Several paths lead to the same failure. An attacker can briefly control a hosted MCP server. A supply chain change can replace a local MCP package. The server operator can change the description on purpose. In each case, the tool list the user approved and the tool list the model uses at runtime are no longer the same.

## Why `ttlMs` and `cacheScope` matter

If the client calls `tools/list` on every agent step, an attacker only needs a short period of control over the server, or one swapped catalog response, to poison the next turn. Cacheable list responses push clients to keep one catalog for `ttlMs`, and to scope that cache with `cacheScope` so reconnects and multi-instance setups do not replace the description set without a clear boundary. The release also notes deterministic list order, which helps keep upstream prompt caches stable, and which also makes it easier to notice when the catalog changed.

Caching alone does not fix the attack. Caching does not prove who produced the catalog, pin a content hash, or show the full description in the UI. An attacker who can wait longer than `ttlMs` can still change the list after the cache expires. A client that ignores `ttlMs` and refreshes on every step gets no protection from the new fields. A client that caches forever without checking integrity can keep a poisoned catalog in memory.

The useful comparison is a package install cool-down, where a registry delays brand-new publishes for a set number of days. A cool-down does not prove a package is safe. It buys time and makes sudden change after trust is established harder to hide. MCP list TTLs can blunt sudden description swaps in the same way, when clients enforce the TTL and treat catalog churn as a security event.

## What clients should do

Spec support is not enough on its own. Client builders should:

1. **Honor `ttlMs`.** Do not re-list tools on every agent step only to stay current.
2. **Hash the approved catalog** at connect or approve time, including tool name, full description, and schemas. Alert or ask the user again when the hash changes after the cache expires.
3. **Show full descriptions at approval time** , not only tool names. Invariant’s UI point still stands.
4. **Pin server and package versions** when the MCP server is distributed as code. A TTL will not protect a client that always pulls a floating`npx` tag.

💡 SEP-2549 is written for cache strategy and prompt-cache stability. The security benefit is a side effect. Implement the fields as if the security benefit were intentional.


## Takeaways

- **Attacker:** Post-approval`tools/list` changes stay useful until clients pin or hash catalogs. Short-lived server compromise is enough when the client refreshes freely.
- **Defender / client builder:** Treat`ttlMs` and`cacheScope` as policy hooks. Pair them with content hashes, and show description diffs the way you would show a changed package tarball.
- **Spec readers:** Keep the[release post](https://blog.modelcontextprotocol.io/posts/2026-07-28/) and the[Invariant tool poisoning write-up](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) open together.

This is a field note on one line item in a large release, not a full threat model. Security readers should not scroll past the cache fields.
