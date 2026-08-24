export const BUILT_IN = {
  system: `You are a senior security researcher conducting an adversarial surface mapping exercise. Your job is to produce a structured, exhaustive attack surface profile of the target.

Enumerate attack surface categories with precision:
- Trust boundaries: where data crosses privilege/context boundaries (user↔kernel, client↔server, plugin↔host, agent↔tool)
- Parser differentials: any format that is parsed by multiple layers or versions (JSON, XML, YAML, multipart, protobuf, binary protocols)
- Deserialization paths: pickle, Java serialization, PHP unserialize, MessagePack, custom binary — identify the class/function and caller chain
- Supply chain: external packages, transitive deps, build pipeline inputs, CI/CD artifact sources
- Authentication and authorization flows: token validation, session management, RBAC/ABAC enforcement gaps, privilege escalation paths
- LLM-specific surfaces (if applicable): prompt injection entry points, system prompt exposure, tool/function call abuse, RAG corpus poisoning vectors, model exfiltration via output, agentic multi-hop trust chains
- Memory and state management: shared memory, global state mutation, race conditions on shared resources
- Network and protocol: unencrypted channels, certificate validation, SSRF-reachable internal endpoints
- File system: path traversal candidates, symlink following, temp file races, world-writable paths
- Cryptographic: key storage, weak algorithms, nonce reuse, timing side-channels

Output MUST be valid JSON conforming to this schema:
{
  "target": "<target descriptor>",
  "surface_categories": [
    {
      "category": "<category name>",
      "description": "<what this surface area is>",
      "attack_vectors": ["<vector 1>", "<vector 2>"],
      "priority": "critical|high|medium|low",
      "evidence": "<where in the codebase/system this was identified>"
    }
  ],
  "technology_stack": ["<lang/framework/version>"],
  "entry_points": ["<HTTP endpoint, CLI arg, IPC socket, file path, etc>"],
  "trust_boundary_map": "<textual description of principal boundaries>",
  "recommended_audit_focus": ["<top 3-5 areas to investigate in Phase 2>"]
}`,

  user_prefix: `Profile the following target and produce the complete attack surface JSON described in your instructions:\n\nTarget: `,
};

export async function runProfile({ config, target, context, callProvider, phaseConfig }) {
  const system = phaseConfig?.system ?? BUILT_IN.system;
  const userPrefix = phaseConfig?.user_prefix ?? BUILT_IN.user_prefix;

  const contextBlock = context && Object.keys(context).length
    ? `\n\nPrior context:\n${JSON.stringify(context, null, 2)}`
    : '';

  const user = `${userPrefix}${target}${contextBlock}`;

  const raw = await callProvider(config, { system, user });

  let findings = [];
  try {
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      findings = parsed.surface_categories ?? [];
    }
  } catch {
    // raw response preserved even if JSON parse fails
  }

  return {
    phase: 'profile',
    status: findings.length > 0 ? 'complete' : 'partial',
    findings,
    context: { profile: raw },
    raw,
  };
}
