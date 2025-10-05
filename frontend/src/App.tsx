import React, { useEffect, useMemo, useState } from "react";
import { BrowserRouter, Routes, Route, Link, useNavigate } from "react-router-dom";
import axios from "axios";
import {
  LogIn, UserPlus, Building2, FileSignature, ShieldCheck,
  PieChart, FileText, Users, Download, Sparkles, Sun, Moon
} from "lucide-react";

const api = axios.create({ baseURL: "/api" });

/* ------------------ Theme Toggle ------------------ */
function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const s = localStorage.getItem("theme");
    return (s === "light" || s === "dark") ? (s as any) : "dark";
  });
  useEffect(() => {
    localStorage.setItem("theme", theme);
    const root = document.documentElement;
    if (theme === "dark") root.classList.add("dark");
    else root.classList.remove("dark");
  }, [theme]);
  return { theme, setTheme };
}
function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  return (
    <button
      aria-label="Toggle theme"
      onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
      className="btn btn-ghost rounded-2xl border border-white/10 px-3 py-2"
      title="Toggle theme"
    >
      {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
    </button>
  );
}

/* ------------------ Auth helper ------------------ */
function useAuth() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("token"));
  useEffect(() => {
    if (token) api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    else delete api.defaults.headers.common["Authorization"];
  }, [token]);
  return {
    token,
    setToken: (t: string | null) => {
      if (t) localStorage.setItem("token", t);
      else localStorage.removeItem("token");
      setToken(t);
    },
  };
}

/* ------------------ Shell ------------------ */
function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="sticky top-0 z-30 border-b border-white/10 bg-ink-950/70 backdrop-blur-xs">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="w-6 h-6 text-white" />
            <span className="text-white">EquityFlow</span>
          </Link>
          <nav className="flex items-center gap-4 text-sm">
            <Link to="/dashboard" className="btn btn-ghost text-white/90">Dashboard</Link>
            <Link to="/documents" className="btn btn-ghost text-white/90">Documents</Link>
            <Link to="/captable" className="btn btn-ghost text-white/90">Cap Table</Link>
            <Link to="/reports" className="btn btn-ghost text-white/90">Reports</Link>
            <ThemeToggle />
          </nav>
        </div>
      </header>
      <main className="flex-1">{children}</main>
      <footer className="border-t border-white/10">
        <div className="max-w-6xl mx-auto px-4 py-6 text-xs text-white/60">
          © {new Date().getFullYear()} EquityFlow. All rights reserved.
        </div>
      </footer>
    </div>
  );
}

/* ------------------ Pages ------------------ */
function Hero() {
  return (
    <div className="py-16">
      <div className="max-w-6xl mx-auto px-4 grid md:grid-cols-2 gap-8 items-center">
        <div>
          <h1 className="text-4xl md:text-5xl font-bold leading-tight">
            Make startup equity simple, secure, and transparent.
          </h1>
          <p className="mt-4 muted">
            Issue SAFEs, Notes, ESOPs, and track ownership — all in one place.
          </p>
          <div className="mt-6 flex gap-3">
            <Link to="/register" className="btn btn-primary">
              <UserPlus className="w-4 h-4" /> Get started
            </Link>
            <Link to="/login" className="btn btn-outline">
              <LogIn className="w-4 h-4" /> Sign in
            </Link>
          </div>
          <div className="mt-6 text-sm muted flex items-center gap-2">
            <Sparkles className="w-4 h-4" /> Built for 2025: cap table engine, digital signing, and data room.
          </div>
        </div>
        <div className="card p-6">
          <img
            alt="dashboard"
            className="w-full rounded-2xl"
            src="https://dummyimage.com/900x520/10121a/333333&text=EquityFlow+Dashboard+Preview"
          />
        </div>
      </div>
    </div>
  );
}

function Register({ setToken }: { setToken: (s: string | null) => void }) {
  const nav = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setErr(null);
    try {
      await api.post("/auth/register", form);
      const { data } = await api.post("/auth/login", { email: form.email, password: form.password });
      setToken(data.access_token);
      nav("/dashboard");
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Registration failed");
    }
  };
  return (
    <div className="max-w-md mx-auto p-6">
      <div className="card p-6">
        <h2 className="text-xl font-semibold mb-4">Create your account</h2>
        <div className="space-y-3">
          <input className="input" placeholder="Full name"
                 value={form.name} onChange={e=>setForm({...form, name:e.target.value})} />
          <input className="input" placeholder="Email"
                 value={form.email} onChange={e=>setForm({...form, email:e.target.value})} />
          <input className="input" placeholder="Password" type="password"
                 value={form.password} onChange={e=>setForm({...form, password:e.target.value})} />
          {err && <div className="text-red-400 text-sm">{err}</div>}
          <button onClick={submit} className="btn btn-primary w-full">Sign up</button>
        </div>
      </div>
    </div>
  );
}

function Login({ setToken }: { setToken: (s: string | null) => void }) {
  const nav = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [err, setErr] = useState<string | null>(null);
  const submit = async () => {
    setErr(null);
    try {
      const { data } = await api.post("/auth/login", form);
      setToken(data.access_token);
      nav("/dashboard");
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Login failed");
    }
  };
  return (
    <div className="max-w-md mx-auto p-6">
      <div className="card p-6">
        <h2 className="text-xl font-semibold mb-4">Welcome back</h2>
        <div className="space-y-3">
          <input className="input" placeholder="Email"
                 value={form.email} onChange={e=>setForm({...form, email:e.target.value})} />
          <input className="input" placeholder="Password" type="password"
                 value={form.password} onChange={e=>setForm({...form, password:e.target.value})} />
          {err && <div className="text-red-400 text-sm">{err}</div>}
          <button onClick={submit} className="btn btn-primary w-full">Sign in</button>
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  const [companies, setCompanies] = useState<any[]>([]);
  const [name, setName] = useState("");
  const [country, setCountry] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    try {
      const { data } = await api.get("/me/memberships");
      setCompanies(data.map((m: any) => m.company));
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to load");
    }
  };
  useEffect(()=>{ load(); }, []);

  const createCompany = async () => {
    setErr(null);
    try {
      await api.post("/companies", { name, country: country || null });
      setName(""); setCountry("");
      await load();
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to create company");
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-4 space-y-6">
      <div className="flex items-center gap-2">
        <Building2 className="w-5 h-5" />
        <h2 className="text-xl font-semibold">Your Companies</h2>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      <div className="grid md:grid-cols-3 gap-4">
        {companies.map((c)=>(
          <div key={c.id} className="card p-4">
            <div className="font-semibold">{c.name}</div>
            <div className="text-xs muted">{c.country}</div>
            <Link to={`/companies/${c.id}`} className="mt-3 inline-block text-sm underline">Open</Link>
          </div>
        ))}
        <div className="card p-4">
          <div className="font-semibold mb-2">Create Company</div>
          <input className="input mb-2" placeholder="Name" value={name} onChange={e=>setName(e.target.value)} />
          <input className="input mb-2" placeholder="Country (optional)" value={country} onChange={e=>setCountry(e.target.value)} />
          <button onClick={createCompany} className="btn btn-primary w-full">Create</button>
        </div>
      </div>
    </div>
  );
}

function CompanyView({ companyId }: { companyId: string }) {
  const [tab, setTab] = useState<"securities"|"people"|"docs">("securities");
  return (
    <div className="max-w-6xl mx-auto p-4">
      <div className="card p-4 flex items-center justify-between">
        <h2 className="text-xl font-semibold flex items-center gap-2"><PieChart className="w-5 h-5" /> Company</h2>
        <div className="flex gap-2">
          <button onClick={()=>setTab("securities")} className={`btn ${tab==="securities"?"btn-primary":"btn-ghost"}`}>Securities</button>
          <button onClick={()=>setTab("people")} className={`btn ${tab==="people"?"btn-primary":"btn-ghost"}`}>People</button>
          <button onClick={()=>setTab("docs")} className={`btn ${tab==="docs"?"btn-primary":"btn-ghost"}`}>Documents</button>
        </div>
      </div>
      <div className="mt-4">
        {tab==="securities" && <Securities companyId={companyId} />}
        {tab==="people" && <People companyId={companyId} />}
        {tab==="docs" && <Documents companyId={companyId} />}
      </div>
    </div>
  );
}

function Securities({ companyId }: { companyId: string }) {
  const [list, setList] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ type: "COMMON_STOCK", holder_email: "", quantity: 0, price: 0, terms_json: "" });
  const load = async () => {
    try {
      const { data } = await api.get(`/companies/${companyId}/securities`);
      setList(data);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to load securities");
    }
  };
  useEffect(()=>{ load(); }, [companyId]);

  const issue = async () => {
    setErr(null);
    try {
      await api.post(`/companies/${companyId}/securities`, {
        type: form.type,
        holder_email: form.holder_email,
        quantity: Number(form.quantity),
        price: Number(form.price),
        terms_json: form.terms_json ? JSON.parse(form.terms_json) : null
      });
      setForm({ type: "COMMON_STOCK", holder_email: "", quantity: 0, price: 0, terms_json: "" });
      await load();
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to issue");
    }
  };

  return (
    <div className="grid md:grid-cols-2 gap-6">
      <div className="card p-4">
        <div className="font-semibold mb-2">Issue Security</div>
        <select className="select mb-2" value={form.type}
                onChange={e=>setForm({...form, type:e.target.value})}>
          <option>SAFE</option>
          <option>CONVERTIBLE_NOTE</option>
          <option>COMMON_STOCK</option>
          <option>PREFERRED_STOCK</option>
          <option>ESOP</option>
        </select>
        <input className="input mb-2" placeholder="Holder email"
               value={form.holder_email} onChange={e=>setForm({...form, holder_email:e.target.value})} />
        <div className="grid grid-cols-2 gap-2">
          <input className="input" placeholder="Quantity" type="number"
                 value={form.quantity as any} onChange={e=>setForm({...form, quantity:e.target.value as any})} />
          <input className="input" placeholder="Price" type="number"
                 value={form.price as any} onChange={e=>setForm({...form, price:e.target.value as any})} />
        </div>
        <textarea className="textarea mt-2" placeholder='Terms JSON (optional)'
                  rows={3} value={form.terms_json} onChange={e=>setForm({...form, terms_json:e.target.value})} />
        {err && <div className="text-red-400 text-sm mt-2">{err}</div>}
        <button onClick={issue} className="mt-3 btn btn-primary w-full">Issue</button>
      </div>
      <div className="space-y-2">
        <div className="font-semibold mb-2">All Securities</div>
        {list.map((s)=>(
          <div key={s.id} className="card p-3 text-sm">
            <div className="flex justify-between">
              <div className="font-semibold">{s.type}</div>
              <div className="muted">{new Date(s.created_at).toLocaleString()}</div>
            </div>
            <div className="mt-1">{s.holder_email}</div>
            <div className="muted">Qty: {s.quantity} · Price: ${s.price}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function People({ companyId }: { companyId: string }) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("employee");
  const [msg, setMsg] = useState<string | null>(null);
  const invite = async () => {
    setMsg(null);
    try {
      await api.post(`/companies/${companyId}/invite`, email, { params: { role }, headers: { "Content-Type": "application/json" } });
      setMsg("Invitation added (placeholder account created if needed).");
      setEmail(""); setRole("employee");
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to invite");
    }
  };
  return (
    <div className="card p-4 max-w-md">
      <div className="font-semibold mb-2">Invite Member</div>
      <input className="input mb-2" placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} />
      <select className="select mb-2" value={role} onChange={e=>setRole(e.target.value)}>
        <option>founder</option>
        <option>investor</option>
        <option>employee</option>
      </select>
      {msg && <div className="text-sm">{msg}</div>}
      <button onClick={invite} className="btn btn-primary w-full">Invite</button>
    </div>
  );
}

function Documents({ companyId }: { companyId: string }) {
  const [docs, setDocs] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ title: "", template_type: "SAFE", payload: `{"investor_email":"","amount":10000,"valuation_cap":5000000,"discount":20}` });
  const [preview, setPreview] = useState<string | null>(null);

  const load = async () => {
    try {
      const { data } = await api.get(`/companies/${companyId}/documents`);
      setDocs(data);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to load docs");
    }
  };
  useEffect(()=>{ load(); }, [companyId]);

  const createDoc = async () => {
    setErr(null);
    try {
      await api.post(`/companies/${companyId}/documents`, {
        title: form.title,
        template_type: form.template_type,
        payload: JSON.parse(form.payload),
      });
      setForm({ title: "", template_type: "SAFE", payload: `{"investor_email":"","amount":10000,"valuation_cap":5000000,"discount":20}` });
      await load();
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to create document");
    }
  };

  const openPreview = async (docId: string) => {
    setPreview(null);
    try {
      const { data } = await api.get(`/documents/${docId}/preview.txt`);
      setPreview(data.text);
    } catch (e: any) {
      setPreview("Failed to preview");
    }
  };

  const startSign = async (docId: string, signer_email: string) => {
    const { data } = await api.post(`/sign/intent`, { document_id: docId, signer_email });
    const ok = confirm("Intent hash generated. Confirm signature?\n\n" + data.intent_hash);
    if (ok) {
      await api.post(`/sign/confirm`, { document_id: docId, signer_email, intent_hash: data.intent_hash });
      alert("Signed and finalized!");
      await load();
    }
  };

  return (
    <div className="grid md:grid-cols-2 gap-6">
      <div className="card p-4">
        <div className="font-semibold mb-2">Create Document</div>
        <input className="input mb-2" placeholder="Title" value={form.title} onChange={e=>setForm({...form, title:e.target.value})} />
        <select className="select mb-2" value={form.template_type} onChange={e=>setForm({...form, template_type:e.target.value})}>
          <option>SAFE</option>
          <option>CONVERTIBLE_NOTE</option>
          <option>GRANT</option>
        </select>
        <textarea className="textarea" rows={6}
                  value={form.payload} onChange={e=>setForm({...form, payload:e.target.value})} />
        {err && <div className="text-red-400 text-sm mt-2">{err}</div>}
        <button onClick={createDoc} className="mt-3 btn btn-primary w-full">Create</button>
      </div>
      <div>
        <div className="font-semibold mb-2">All Documents</div>
        <div className="grid gap-2">
          {docs.map((d)=>(
            <div key={d.id} className="card p-3 text-sm">
              <div className="flex justify-between items-center">
                <div>
                  <div className="font-semibold">{d.title}</div>
                  <div className="muted">{d.template_type} · {new Date(d.created_at).toLocaleString()}</div>
                </div>
                {d.finalized_pdf_path ? (
                  <a href={`/api/documents/${d.id}/download`} className="text-sm flex items-center gap-1 underline">
                    <Download className="w-4 h-4" /> Download
                  </a>
                ) : (
                  <button onClick={()=>openPreview(d.id)} className="text-sm underline">Preview</button>
                )}
              </div>
              {!d.finalized_pdf_path && (
                <div className="mt-2 flex gap-2">
                  <input className="input flex-1" placeholder="Signer email" id={`signer-${d.id}`} />
                  <button
                    onClick={()=>startSign(d.id, (document.getElementById(`signer-${d.id}`) as HTMLInputElement).value)}
                    className="btn btn-primary">
                      Sign
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
        {preview && (
          <div className="mt-4 card p-4">
            <div className="font-semibold mb-2">Preview</div>
            <pre className="text-xs whitespace-pre-wrap">{preview}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

function CapTable() {
  const [companyId, setCompanyId] = useState("");
  const [snapshot, setSnapshot] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = async () => {
    setErr(null); setSnapshot(null);
    try {
      const { data: memberships } = await api.get("/me/memberships");
      const cid = companyId || (memberships[0]?.company?.id || "");
      if (!cid) { setErr("No company available"); return; }
      const { data } = await api.get(`/companies/${cid}/captable`);
      setSnapshot(data);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to compute cap table");
    }
  };
  useEffect(()=>{ load(); }, []);
  return (
    <div className="max-w-4xl mx-auto p-4 space-y-3">
      <div className="flex items-center gap-2">
        <PieChart className="w-5 h-5" />
        <h2 className="text-xl font-semibold">Cap Table</h2>
      </div>
      <div className="card p-3 flex gap-2">
        <input className="input flex-1" placeholder="Company ID (optional)"
               value={companyId} onChange={e=>setCompanyId(e.target.value)} />
        <button onClick={load} className="btn btn-outline">Refresh</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      {snapshot && (
        <div className="card p-4">
          <div className="muted">Total Shares: {snapshot.total_shares}</div>
          <div className="mt-2 grid gap-2">
            {snapshot.entries.map((e:any, i:number)=>(
              <div key={i} className="text-sm grid md:grid-cols-4 border border-white/10 rounded-2xl p-2">
                <div>{e.holder_email}</div>
                <div className="muted">{e.security_type}</div>
                <div>Qty: {e.quantity}</div>
                <div>Value: ${e.value}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Reports() {
  const [companyId, setCompanyId] = useState("");
  const [out, setOut] = useState<any|null>(null);
  const [err, setErr] = useState<string|null>(null);
  const run = async (type: "ownership"|"dataroom") => {
    setErr(null); setOut(null);
    try {
      const { data: memberships } = await api.get("/me/memberships");
      const cid = companyId || (memberships[0]?.company?.id || "");
      if (!cid) { setErr("No company available"); return; }
      const { data } = await api.post("/reports/generate", { company_id: cid, report_type: type });
      setOut(data);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to generate");
    }
  };
  return (
    <div className="max-w-4xl mx-auto p-4 space-y-3">
      <div className="flex items-center gap-2">
        <FileText className="w-5 h-5" />
        <h2 className="text-xl font-semibold">Reports & Data Room</h2>
      </div>
      <div className="card p-3 grid md:grid-cols-3 gap-2">
        <input className="input" placeholder="Company ID (optional)"
               value={companyId} onChange={e=>setCompanyId(e.target.value)} />
        <button onClick={()=>run("ownership")} className="btn btn-outline">Ownership Report</button>
        <button onClick={()=>run("dataroom")} className="btn btn-outline">Data Room Summary</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      {out && (<pre className="card p-4 text-xs whitespace-pre-wrap">{JSON.stringify(out, null, 2)}</pre>)}
    </div>
  );
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const [ok, setOk] = useState<boolean>(false);
  useEffect(()=>{ api.get("/healthz").then(()=>setOk(true)).catch(()=>setOk(true)); },[]);
  return <>{children}</>
}

export default function App() {
  const { token, setToken } = useAuth();
  return (
    <BrowserRouter>
      <PageShell>
        <Routes>
          <Route path="/" element={<Hero />} />
          <Route path="/register" element={<Register setToken={setToken} />} />
          <Route path="/login" element={<Login setToken={setToken} />} />
          <Route path="/dashboard" element={<RequireAuth><Dashboard /></RequireAuth>} />
          <Route path="/companies/:id" element={<CompanyRoute />} />
          <Route path="/captable" element={<RequireAuth><CapTable /></RequireAuth>} />
          <Route path="/documents" element={<RequireAuth><Documents companyId={"_choose_"} /></RequireAuth>} />
          <Route path="/reports" element={<RequireAuth><Reports /></RequireAuth>} />
        </Routes>
      </PageShell>
    </BrowserRouter>
  );
}

function CompanyRoute() {
  const id = window.location.pathname.split("/").pop() || "";
  return <CompanyView companyId={id} />
}
