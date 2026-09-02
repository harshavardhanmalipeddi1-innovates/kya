# Multi-agent security graph
from typing import Dict, Any, List

class AgentGraph:
    def __init__(self):
        self._agents = {}
        self._delegations = {}
    def register_agent(self, agent_id, metadata):
        self._agents[agent_id] = metadata
    def add_delegation(self, delegator, delegatee, scope):
        if delegator not in self._delegations:
            self._delegations[delegator] = []
        self._delegations[delegator].append({"delegatee": delegatee, "scope": scope})
    def check_authority(self, agent_id, action):
        agent = self._agents.get(agent_id)
        if not agent: return {"authorized": False, "reason": "Not registered"}
        if action in agent.get("allowed_actions", []): return {"authorized": True, "reason": "Direct"}
        for d in self._delegations.get(agent_id, []):
            if action in d["scope"]: return {"authorized": True, "reason": "Delegated"}
        return {"authorized": False, "reason": "No authority"}
    def detect_circular_delegation(self):
        cycles = []
        visited = set()
        path = []
        def dfs(node):
            if node in path:
                cycles.append(" -> ".join(path[path.index(node):] + [node]))
                return
            if node in visited: return
            visited.add(node)
            path.append(node)
            for d in self._delegations.get(node, []): dfs(d["delegatee"])
            path.pop()
        for a in self._delegations: dfs(a)
        return cycles
    def get_agent_count(self): return len(self._agents)
    def get_delegation_count(self): return sum(len(v) for v in self._delegations.values())

agent_graph = AgentGraph()
