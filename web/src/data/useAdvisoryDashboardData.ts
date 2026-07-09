import { useEffect, useMemo, useState } from "react";
import { config } from "../config";
import { loadAdvisoryDashboardData } from "./loader";
import type { AdvisoryDashboardPayload, DashboardPackage } from "./types";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useAdvisoryDashboardData() {
  const [payload, setPayload] = useState<AdvisoryDashboardPayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    loadAdvisoryDashboardData(config.dashboardDataUrl)
      .then((data) => {
        setPayload(data);
        setLoadError(null);
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);

  const packages = useMemo<DashboardPackage[]>(() => {
    if (!payload) return [];
    return Object.values(payload.packages).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
  }, [payload]);

  return { payload, packages, loadError };
}
