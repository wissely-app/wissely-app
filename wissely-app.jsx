import { useState } from "react";

const TOOLS = [
  {
    id: "analyze", icon: "🔍", label: "Invoice Analyzer",
    desc: "Extract every detail instantly",
    placeholder: "Paste your invoice here...\n\nExample:\nInvoice #INV-2026-0547\nFrom: TechSupplies Ltd\nTo: Your Business\nDate: May 29, 2026\nDue: June 28, 2026\nMacBook Pro x2: $3,998\nSoftware License: $1,200\nSupport Package: $299\nTax (8.5%): $512\nTOTAL: $6,544",
    prompt: (t) => `You are a financial expert. Analyze this invoice clearly. Extract: vendor, invoice number, date, due date, every line item, subtotal, tax, total, payment terms. Flag any red flags or issues. Plain English only, no jargon. Text: ${t}`
  },
  {
    id: "categorize", icon: "🗂️", label: "Expense Clarity",
    desc: "Sort expenses for tax and accounting",
    placeholder: "Paste your expenses here...\n\nExample:\nSoftware tools: $890\nOffice rent: $2,100\nContractor fees: $4,200\nMarketing: $500\nTravel: $350\nEquipment: $1,800",
    prompt: (t) => `You are an accountant. Categorize these expenses clearly for tax purposes. For each: category name, tax deductible yes or no, and any notes. Give a clear totals summary by category. Plain English only. Text: ${t}`
  },
  {
    id: "report", icon: "📊", label: "Finance Report",
    desc: "A clear summary you can actually read",
    placeholder: "Paste your financial data here...\n\nExample:\nRevenue this month: $12,400\nTotal expenses: $8,900\nUnpaid invoices: $3,200\nRent: $2,100\nContractors: $4,200\nTax paid: $0",
    prompt: (t) => `You are a CFO. Write a clear plain English financial report. Explain what the numbers mean, what is going well, what needs attention, and give 3 specific action items. No financial jargon at all. Text: ${t}`
  },
  {
    id: "email", icon: "📧", label: "Payment Request",
    desc: "A follow-up that gets you paid",
    placeholder: "Paste your invoice details here...\n\nExample:\nClient: ABC Corp\nInvoice amount: $3,500\nDays overdue: 15\nProject: Website redesign\nPrevious reminders: 1",
    prompt: (t) => `You are a professional business communicator. Write a firm but polite payment follow-up email with subject line. Sound human and professional. Include payment details and a clear call to action. Invoice info: ${t}`
  },
  {
    id: "fraud", icon: "🚨", label: "Fraud Detection",
    desc: "Catch errors before they cost you",
    placeholder: "Paste your invoices or transactions here...\n\nExample:\nInvoice A: $2,500 - Supplier X - May 1\nInvoice B: $2,500 - Supplier X - May 1\nInvoice C: $8,999 - Unknown Vendor - May 3\nInvoice D: $450 - Office Supplies Co",
    prompt: (t) => `You are a forensic accountant. Check this financial data for: duplicates, calculation errors, unusual amounts, missing info, and red flags. Rate each issue Low, Medium or High risk. Be specific and clear. Plain English. Text: ${t}`
  },
  {
    id: "forecast", icon: "📈", label: "Cash Flow Forecast",
    desc: "See your 30, 60 and 90 day picture",
    placeholder: "Paste your financial data here...\n\nExample:\nCurrent balance: $18,500\nMonthly expenses: $6,200\nExpected payments: $12,000\nOverdue invoices: $4,500\nUpcoming tax: $2,800\nNew equipment: $3,000",
    prompt: (t) => `You are a financial forecaster. Give a clear 30, 60 and 90 day cash flow forecast. Tell the owner: will they have enough cash, when are the risk points, and exactly what to do. Specific numbers. Plain English. Text: ${t}`
  },
];

const MODELS = [
  { id: "claude", label: "Claude",  available: true,  color: "#c9a84c" },
  { id: "gpt4",   label: "GPT-4",   available: false, color: "#10b981" },
  { id: "gemini", label: "Gemini",  available: false, color: "#3b82f6" },
];

async function callAI(prompt) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  return data.content?.map(b => b.text || "").join("\n") || "No response.";
}

export default function WisselyApp() {
  const [tool,    setTool]    = useState(TOOLS[0]);
  const [model,   setModel]   = useState(MODELS[0]);
  const [input,   setInput]   = useState("");
  const [output,  setOutput]  = useState("");
  const [loading, setLoading] = useState(false);
  const [copied,  setCopied]  = useState(false);
  const [error,   setError]   = useState("");
  const [history, setHistory] = useState([]);

  const run = async () => {
    if (!input.trim()) { setError("Paste your financial data first."); return; }
    setError(""); setLoading(true); setOutput("");
    try {
      const result = await callAI(tool.prompt(input));
      setOutput(result);
      setHistory(h => [{ tool: tool.label, icon: tool.icon, preview: input.slice(0, 50) + "...", output: result }, ...h.slice(0, 4)]);
    } catch { setError("Something went wrong. Please try again."); }
    setLoading(false);
  };

  const copy = () => { navigator.clipboard.writeText(output); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const clear = () => { setInput(""); setOutput(""); setError(""); };

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,600;0,700;1,400&family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        :root{
          --ink:#0c0c0a;
          --ink2:#181812;
          --sage:#2d4a3e;
          --sage2:#3d6b58;
          --gold:#c9a84c;
          --gold2:#e8c97a;
          --gold3:#f5e0a0;
          --cream:#f8f6f0;
          --cream2:#ede9df;
        }
        body{background:var(--cream);font-family:'DM Sans',sans-serif;color:var(--ink);margin:0}
        ::-webkit-scrollbar{width:5px}
        ::-webkit-scrollbar-thumb{background:#dedad0;border-radius:3px}
        textarea::placeholder{color:#c0bdb0;font-family:'DM Mono',monospace;font-size:12px}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
        .tool-btn{background:transparent;border:1px solid transparent;border-radius:12px;padding:12px 14px;text-align:left;cursor:pointer;transition:all 0.15s;display:flex;align-items:flex-start;gap:10px;width:100%;color:#2a2a20}
        .tool-btn:hover{background:rgba(45,74,62,0.06);border-color:rgba(45,74,62,0.2)}
        .tool-btn.active{background:#2d4a3e;border-color:#2d4a3e;box-shadow:0 2px 12px rgba(45,74,62,0.3)}
        .hist-item{background:#fff;border:1px solid #dedad0;border-radius:8px;padding:10px 12px;margin-bottom:7px;cursor:pointer;transition:all 0.15s}
        .hist-item:hover{background:var(--cream2);border-color:var(--sage)}
        .model-btn{background:transparent;border:1px solid rgba(255,255,255,0.1);border-radius:100px;padding:5px 14px;font-family:'DM Mono',monospace;font-size:11px;cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:6px}
        .model-btn.active{border-color:rgba(201,168,76,0.4);background:rgba(201,168,76,0.08);color:#e8c97a}
        .model-btn:not(.active){color:rgba(255,255,255,0.3)}
        .generate-btn{width:100%;border:none;border-radius:0 0 14px 14px;padding:16px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.2s;display:flex;align-items:center;justify-content:center;gap:10px;letter-spacing:0.3px}
        .generate-btn:not(:disabled){background:linear-gradient(135deg,#c9a84c,#a8873c);color:#0c0c0a;box-shadow:0 4px 24px rgba(201,168,76,0.3)}
        .generate-btn:not(:disabled):hover{background:linear-gradient(135deg,#e8c97a,#c9a84c);transform:translateY(-1px);box-shadow:0 8px 32px rgba(201,168,76,0.4)}
        .generate-btn:disabled{background:rgba(201,168,76,0.15);color:rgba(255,255,255,0.35);cursor:not-allowed}
        .clear-btn{background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.2);border-radius:8px;padding:6px 14px;color:rgba(255,255,255,0.7);font-size:11px;font-family:'DM Mono',monospace;cursor:pointer;transition:all 0.15s}
        .clear-btn:hover{background:rgba(255,255,255,0.2);color:#fff}
        .copy-btn{background:transparent;border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:6px 14px;font-size:11px;font-family:'DM Mono',monospace;cursor:pointer;transition:all 0.15s}
        .copy-btn.copied{border-color:rgba(74,222,128,0.5);color:#4ade80;background:rgba(74,222,128,0.15)}
        .copy-btn:not(.copied){color:rgba(255,255,255,0.8)}
        .copy-btn:hover{border-color:rgba(255,255,255,0.25)}
        @media(max-width:700px){
          .app-body{grid-template-columns:1fr !important}
          .sidebar{display:flex;flex-direction:row;overflow-x:auto;gap:8px;padding-bottom:8px}
          .tool-btn{min-width:140px;flex-shrink:0}
          .sidebar-history{display:none}
          .stats-row{grid-template-columns:repeat(3,1fr) !important}
        }
      `}</style>

      {/* ── NAV ── */}
      <div style={{background:"rgba(12,12,10,0.98)",backdropFilter:"blur(16px)",borderBottom:"1px solid rgba(201,168,76,0.1)",padding:"0 28px",height:58,display:"flex",alignItems:"center",justifyContent:"space-between",position:"sticky",top:0,zIndex:100}}>
        <a href="https://wissely.com" style={{display:"flex",alignItems:"center",gap:10,textDecoration:"none"}}>
          <div style={{width:30,height:30,background:"var(--sage)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'Cormorant Garamond',serif",fontSize:15,fontWeight:700,color:"var(--gold)"}}>W</div>
          <span style={{fontFamily:"'Cormorant Garamond',serif",fontSize:20,fontWeight:700,color:"#fff",letterSpacing:"-0.5px"}}>Wissely</span>
          <span style={{fontSize:10,color:"rgba(255,255,255,0.25)",fontFamily:"'DM Mono',monospace",letterSpacing:"1.5px",marginLeft:4}}>APP</span>
        </a>
        <div style={{display:"flex",gap:8}}>
          {MODELS.map(m => (
            <button key={m.id} className={`model-btn${model.id===m.id?" active":""}`}
              onClick={() => m.available && setModel(m)}
              style={{opacity:m.available?1:0.35,cursor:m.available?"pointer":"not-allowed"}}>
              <span style={{width:5,height:5,borderRadius:"50%",background:m.available?m.color:"#555",display:"inline-block",animation:model.id===m.id?"pulse 2s infinite":"none"}}/>
              {m.label}{!m.available&&" · soon"}
            </button>
          ))}
        </div>
      </div>

      {/* ── BODY ── */}
      <div className="app-body" style={{maxWidth:1060,margin:"0 auto",padding:"24px 20px 60px",display:"grid",gridTemplateColumns:"220px 1fr",gap:20,alignItems:"start"}}>

        {/* ── SIDEBAR ── */}
        <div className="sidebar" style={{display:"flex",flexDirection:"column",gap:4}}>
          <div style={{fontSize:10,color:"#aaa898",fontFamily:"'DM Mono',monospace",letterSpacing:"2px",textTransform:"uppercase",marginBottom:10,paddingLeft:4}}>Tools</div>
          {TOOLS.map(t => (
            <button key={t.id} className={`tool-btn${tool.id===t.id?" active":""}`}
              onClick={() => { setTool(t); setOutput(""); setError(""); setInput(""); }}>
              <span style={{fontSize:17,lineHeight:1,marginTop:1,flexShrink:0}}>{t.icon}</span>
              <div>
                <div style={{fontSize:13,fontWeight:500,color:tool.id===t.id?"#f5e0a0":"#1a1a12",marginBottom:2,fontWeight:tool.id===t.id?600:400}}>{t.label}</div>
                <div style={{fontSize:11,color:tool.id===t.id?"rgba(255,255,255,0.8)":"#7a7a66",lineHeight:1.4}}>{t.desc}</div>
              </div>
            </button>
          ))}

          {/* History */}
          {history.length > 0 && (
            <div className="sidebar-history" style={{marginTop:20,borderTop:"1px solid #dedad0",paddingTop:16}}>
              <div style={{fontSize:10,color:"#aaa898",fontFamily:"'DM Mono',monospace",letterSpacing:"2px",textTransform:"uppercase",marginBottom:10,paddingLeft:4}}>Recent</div>
              {history.map((h,i) => (
                <div key={i} className="hist-item" onClick={() => setOutput(h.output)}>
                  <div style={{fontSize:10,color:"var(--gold)",fontFamily:"'DM Mono',monospace",letterSpacing:"1px",marginBottom:3}}>{h.icon} {h.tool}</div>
                  <div style={{fontSize:11,color:"#7a7a66",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.preview}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── MAIN ── */}
        <div style={{display:"flex",flexDirection:"column",gap:14}}>

          {/* Stats */}
          <div className="stats-row" style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
            {[["10hrs","Saved weekly"],["30s","Per analysis"],["$29","Per month"]].map(([val,label]) => (
              <div key={label} style={{background:"#ffffff",border:"1px solid var(--cream3, #dedad0)",borderRadius:12,padding:"14px 16px",textAlign:"center",boxShadow:"0 2px 12px rgba(0,0,0,0.04)"}}>
                <span style={{fontFamily:"'Cormorant Garamond',serif",fontSize:26,fontWeight:700,color:"var(--sage)",display:"block",lineHeight:1,letterSpacing:"-0.5px"}}>{val}</span>
                <span style={{fontSize:10,color:"#7a7a66",fontFamily:"'DM Mono',monospace",letterSpacing:"1.5px",textTransform:"uppercase",marginTop:5,display:"block"}}>{label}</span>
              </div>
            ))}
          </div>

          {/* Input Card */}
          <div style={{borderRadius:14,overflow:"hidden",border:"1px solid #dedad0",boxShadow:"0 4px 24px rgba(0,0,0,0.06)"}}>

            {/* Tool Header */}
            <div style={{background:"var(--sage)",borderBottom:"1px solid rgba(45,74,62,0.5)",padding:"14px 18px",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
              <div style={{display:"flex",alignItems:"center",gap:10}}>
                <span style={{fontSize:20}}>{tool.icon}</span>
                <div>
                  <div style={{fontSize:14,fontWeight:600,color:"#ffffff"}}>{tool.label}</div>
                  <div style={{fontSize:11,color:"rgba(255,255,255,0.7)",marginTop:1}}>{tool.desc}</div>
                </div>
              </div>
              <button className="clear-btn" onClick={clear}>Clear</button>
            </div>

            {/* Textarea */}
            <div style={{background:"#ffffff"}}>
              <textarea
                value={input}
                onChange={e => { setInput(e.target.value); setError(""); }}
                onKeyDown={e => e.ctrlKey && e.key==="Enter" && run()}
                placeholder={tool.placeholder}
                style={{width:"100%",background:"transparent",border:"none",padding:"18px 20px",color:"#2a2a20",fontSize:13,fontFamily:"'DM Mono',monospace",lineHeight:1.8,resize:"vertical",outline:"none",minHeight:190}}
              />
              <div style={{padding:"10px 20px",borderTop:"1px solid #ede9df",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <span style={{fontSize:11,color:"#aaa898",fontFamily:"'DM Mono',monospace"}}>{input.length} chars · Ctrl+Enter to run</span>
                {error && <span style={{fontSize:12,color:"#f87171",fontFamily:"'DM Mono',monospace"}}>⚠ {error}</span>}
              </div>
            </div>

            {/* Generate Button */}
            <button className="generate-btn" onClick={run} disabled={loading}>
              {loading
                ? <><span style={{display:"inline-block",animation:"spin 1s linear infinite",fontSize:16}}>⟳</span> Analyzing with {model.label}...</>
                : <>{tool.icon} Run {tool.label}</>
              }
            </button>
          </div>

          {/* Output */}
          {output && (
            <div style={{background:"#ffffff",border:"1px solid #dedad0",borderRadius:14,overflow:"hidden",animation:"fadeUp 0.35s ease",boxShadow:"0 4px 24px rgba(0,0,0,0.06)"}}>
              <div style={{background:"var(--sage)",borderBottom:"1px solid rgba(45,74,62,0.3)",padding:"13px 18px",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <div style={{width:7,height:7,borderRadius:"50%",background:"#4ade80",animation:"pulse 2s infinite"}}/>
                  <span style={{fontSize:11,color:"rgba(255,255,255,0.85)",fontFamily:"'DM Mono',monospace",letterSpacing:"0.5px"}}>{tool.label} · {model.label} · {new Date().toLocaleTimeString()}</span>
                </div>
                <button className={`copy-btn${copied?" copied":""}`} onClick={copy}>
                  {copied ? "✓ Copied" : "Copy"}
                </button>
              </div>
              <div style={{padding:"22px",fontSize:13.5,lineHeight:1.9,color:"#2a2a20",whiteSpace:"pre-wrap",maxHeight:440,overflowY:"auto",fontFamily:"'DM Mono',monospace"}}>
                {output}
              </div>
            </div>
          )}

          {/* Empty State */}
          {!output && !loading && (
            <div style={{border:"2px dashed #dedad0",borderRadius:14,padding:"52px 24px",textAlign:"center",background:"#fff"}}>
              <div style={{fontSize:36,marginBottom:12,opacity:0.35}}>💡</div>
              <div style={{fontSize:13,color:"#aaa898",fontFamily:"'DM Mono',monospace",letterSpacing:"0.5px",marginBottom:6}}>Select a tool and paste your financial data</div>
              <div style={{fontSize:11,color:"#c8c4b8",fontFamily:"'DM Mono',monospace"}}>Examples are pre-loaded in the text box</div>
            </div>
          )}

          {/* Footer note */}
          <div style={{textAlign:"center",paddingTop:8}}>
            <span style={{fontSize:10,color:"#aaa898",fontFamily:"'DM Mono',monospace",letterSpacing:"1.5px"}}>WISSELY.COM · YOUR FINANCES, FINALLY CLEAR · 2026</span>
          </div>
        </div>
      </div>
    </>
  );
}
