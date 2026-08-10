import { useEffect, useState } from "react";
import { AdvisoryDashboard } from "./components/AdvisoryDashboard";
import { LoadingToast } from "./components/LoadingToast";
import { PurlMapperView } from "./components/PurlMapperView";
import { Glyph, useTheme } from "./components/Primitives";

type AppView = "advisory" | "mapper";

function viewFromLocation(): AppView {
  const hash = window.location.hash.replace(/^#\/?/, "").toLowerCase();
  if (hash.startsWith("mapper")) return "mapper";
  if (hash.startsWith("purl")) return "mapper";
  return "advisory";
}

function routeForView(view: AppView): string {
  return view === "mapper" ? "#/mapper" : "#/advisory";
}

export function App() {
  const theme = useTheme();
  const [activeView, setActiveView] = useState<AppView>(() => viewFromLocation());
  const t = theme.t;

  useEffect(() => {
    function syncView() {
      setActiveView(viewFromLocation());
    }
    window.addEventListener("hashchange", syncView);
    window.addEventListener("popstate", syncView);
    return () => {
      window.removeEventListener("hashchange", syncView);
      window.removeEventListener("popstate", syncView);
    };
  }, []);

  function navigate(view: AppView): void {
    const route = routeForView(view);
    if (window.location.hash !== route) {
      window.history.pushState(null, "", route);
    }
    setActiveView(view);
  }

  const navButton = (view: AppView, label: string) => {
    const active = activeView === view;
    return (
      <button
        onClick={() => navigate(view)}
        style={{
          color: active ? t.fg1 : t.fg2,
          padding: "5px 8px",
          borderRadius: 6,
          background: active ? t.inset : "transparent",
          border: `1px solid ${active ? t.border : "transparent"}`,
          cursor: "pointer",
          fontSize: 11,
          fontWeight: 700,
          textTransform: "uppercase",
          fontFamily: "Inter, sans-serif",
        }}
      >
        {label}
      </button>
    );
  };

  return (
    <div
      className={theme.dark ? "dark-scope" : ""}
      style={{
        background: t.page,
        height: "100vh",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 18px",
          borderBottom: `1px solid ${t.border}`,
          background: t.surface,
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              minWidth: 170,
              color: t.fg1,
              fontSize: 13,
              fontWeight: 800,
              letterSpacing: "0",
            }}
          >
            <span
              style={{
                width: 24,
                height: 24,
                borderRadius: 6,
                border: `1px solid ${t.border}`,
                background: t.inset,
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                color: t.fg2,
              }}
            >
              <Glyph name={activeView === "advisory" ? "db" : "edit"} size={13} />
            </span>
            {activeView === "advisory" ? "Advisory Channel" : "PURL Mapper"}
          </div>

          <nav
            style={{
              display: "flex",
              gap: 6,
              fontSize: 11,
              fontWeight: 600,
              textTransform: "uppercase",
            }}
          >
            {navButton("advisory", "Advisory Dashboard")}
            {navButton("mapper", "PURL Mapper")}
          </nav>
        </div>

        <button
          onClick={() => theme.setDark(!theme.dark)}
          style={{
            background: t.surface2,
            border: `1px solid ${t.border}`,
            color: t.fg1,
            borderRadius: 8,
            width: 30,
            height: 30,
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            fontSize: 14,
          }}
          title="Toggle theme"
        >
          {theme.dark ? "☀" : "☾"}
        </button>
      </header>

      {activeView === "advisory" ? (
        <div style={{ flex: 1, minHeight: 0 }}>
          <AdvisoryDashboard theme={theme} />
        </div>
      ) : (
        <PurlMapperView theme={theme} />
      )}

      <LoadingToast theme={theme} />
    </div>
  );
}
