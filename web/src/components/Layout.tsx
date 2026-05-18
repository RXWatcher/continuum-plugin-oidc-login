import { Outlet, Link } from "react-router";
import { ArrowLeft } from "lucide-react";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { loadIdentity, currentUser } from "@/lib/identity";
import { api } from "@/lib/api";

type BrandConfig = { display_name: string };

export default function Layout() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    loadIdentity()
      .then(() => setReady(true))
      .catch(() => setReady(true));
  }, []);
  const { data: cfg } = useQuery({
    queryKey: ["config-summary-for-brand"],
    queryFn: () => api.get<BrandConfig>("/api/v1/admin/config-summary"),
    enabled: ready && !!currentUser()?.isAdmin,
  });
  if (!ready) return null;
  const user = currentUser();
  if (!user?.isAdmin) {
    return (
      <div className="bg-background text-foreground min-h-screen p-12 text-center">
        <h1 className="text-xl font-semibold">Admin access required</h1>
        <p className="text-muted-foreground mt-2">
          You need an admin role to view this page.
        </p>
        <a href="/admin/plugins" className="mt-4 inline-block underline">
          &larr; Back to Continuum plugins
        </a>
      </div>
    );
  }
  return (
    <div className="bg-background text-foreground relative min-h-[100dvh] overflow-x-hidden">
      <div className="from-primary/6 pointer-events-none fixed inset-x-0 top-0 z-0 h-40 bg-gradient-to-b to-transparent blur-3xl" />
      <header className="glass-dark border-border/70 sticky top-0 z-30 mx-3 mt-3 rounded-2xl border px-4 py-3 sm:mx-6 lg:mx-8">
        <div className="flex flex-wrap items-center gap-3">
          <a
            href="/admin/plugins"
            className="text-muted-foreground hover:bg-surface-hover hover:text-foreground inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium transition-colors"
            title="Back to Continuum plugins"
          >
            <ArrowLeft className="size-4" />
            <span className="hidden sm:inline">Continuum</span>
          </a>
          <span className="text-border/60" aria-hidden>
            /
          </span>
          <Link to="/" className="text-base font-semibold tracking-tight">
            {cfg?.display_name || "OIDC Login"}{" "}
            <span className="text-muted-foreground ml-1 text-xs">admin</span>
          </Link>
        </div>
      </header>
      <main className="relative z-10 mx-auto max-w-[1100px] space-y-6 px-4 pb-12 pt-2 md:px-6 lg:px-8">
        <Outlet />
      </main>
    </div>
  );
}
