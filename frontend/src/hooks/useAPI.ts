import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Summary, Agent, BlackboardData, Mission, Skill, CombinedState } from "../api/types";

/** Auto-refreshing hook — polls every 5s */
function useAuto<T>(fetcher: () => Promise<T>, key: string, interval = 5000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval>;

    async function refresh() {
      try {
        const d = await fetcher();
        if (active) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (active) setError((e as Error).message);
      } finally {
        if (active) setLoading(false);
      }
    }

    refresh();
    timer = setInterval(refresh, interval);

    return () => {
      active = false;
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return { data, error, loading };
}

export function useSummary() {
  return useAuto(() => api.summary(), "summary");
}

export function useAgents() {
  return useAuto(() => api.agents(), "agents");
}

export function useBlackboard() {
  return useAuto(() => api.blackboard(), "blackboard");
}

export function useMissions() {
  return useAuto(() => api.missions(), "missions");
}

export function useSkills() {
  return useAuto(() => api.skills(), "skills");
}

export function useCombinedState(agentId: string, channelId: string) {
  return useAuto(() => api.state(agentId, channelId), `state/${agentId}/${channelId}`, 3000);
}

export type { Summary, Agent, BlackboardData, Mission, Skill, CombinedState };
