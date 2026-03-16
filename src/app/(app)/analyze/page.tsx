'use client';

import { useState, useRef } from 'react';
import { Play, Upload, FileCode, AlertCircle, Sparkles, CheckCircle2, RotateCcw, ChevronDown } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

// --- TYPES FOR YOUR FLASK API ---
interface ScanResult {
    line_number: number;
    code: string;
    label: number;
    label_name: string;
    confidence: number;
}

const LANGUAGES = {
    python: {
        name: 'Python',
        version: '3.10',
        snippet: `import sqlite3

def get_user(id):
    clean = SQLSanitizer.clean(id)
    query = 'SELECT * FROM users WHERE id=' + clean
    cursor.execute(query)
    return cursor.fetchone()`
    },
    // Keep your other languages here...
    javascript: {
        name: 'JavaScript',
        version: 'Node.js 18',
        snippet: `const express = require('express');\nconst app = express();\nconst db = require('./db');\n\napp.get('/search', (req, res) => {\n    const query = req.query.q;\n    const sql = "SELECT * FROM items WHERE name = '" + query + "'";\n    db.query(sql, (err, result) => {\n        if (err) throw err;\n        res.send(result);\n    });\n});`
    }
};

type LanguageKey = keyof typeof LANGUAGES;

export default function AnalyzePage() {
    const [selectedLang, setSelectedLang] = useState<LanguageKey>('python');
    const [code, setCode] = useState(LANGUAGES['python'].snippet);
    const [isDropdownOpen, setIsDropdownOpen] = useState(false);

    // API States
    const [analyzing, setAnalyzing] = useState(false);
    const [analyzed, setAnalyzed] = useState(false);
    const [scanResults, setScanResults] = useState<ScanResult[]>([]);

    // Fix States
    const [showFix, setShowFix] = useState(false);
    const [isFixing, setIsFixing] = useState(false);
    const [fixedCode, setFixedCode] = useState("");

    const textAreaRef = useRef<HTMLTextAreaElement>(null);

    // --- PHASE 1: SCAN API CALL ---
    const handleAnalyze = async () => {
        setAnalyzing(true);
        setAnalyzed(false);
        setScanResults([]);

        try {
            const apiUrl = process.env.NEXT_PUBLIC_API_URL || "https://shaiiiikh1305-backend.hf.space";
            const res = await fetch(`${apiUrl}/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code })
            });
            const data = await res.json();

            if (data.scan_results) {
                setScanResults(data.scan_results);
            }
        } catch (error) {
            console.error("Scan failed:", error);
        } finally {
            setAnalyzing(false);
            setAnalyzed(true);
        }
    };

    // --- PHASE 2: FIX API CALL ---
    const handleGenerateFix = async () => {
        setShowFix(true);
        setIsFixing(true);
        setFixedCode("");

        try {
            const apiUrl = process.env.NEXT_PUBLIC_API_URL || "https://shaiiiikh1305-backend.hf.space";
            const res = await fetch(`${apiUrl}/fix`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code, scan_results: scanResults })
            });
            const data = await res.json();

            if (data.fixed_code) {
                setFixedCode(data.fixed_code);
            } else {
                setFixedCode("No fix generated.");
            }
        } catch (error) {
            console.error("Fix failed:", error);
            setFixedCode("Error connecting to the cloud AI model.");
        } finally {
            setIsFixing(false);
        }
    };

    const resetCode = () => {
        setCode(LANGUAGES[selectedLang].snippet);
        setAnalyzed(false);
        setShowFix(false);
        setScanResults([]);
    };

    const handleLanguageChange = (lang: LanguageKey) => {
        setSelectedLang(lang);
        setCode(LANGUAGES[lang].snippet);
        setIsDropdownOpen(false);
        setAnalyzed(false);
        setShowFix(false);
        setScanResults([]);
    };

    // Filter out safe lines so we only show issues in the right panel
    const issues = scanResults.filter(res => res.label !== 1);

    return (
        <div className="h-[calc(100vh-4rem)] flex flex-col lg:flex-row overflow-hidden relative">
            {/* Background Elements */}
            <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-20">
                <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-primary/20 blur-[120px] rounded-full animate-pulse-glow"></div>
                <div className="absolute bottom-1/4 left-1/4 w-96 h-96 bg-purple-500/10 blur-[120px] rounded-full animate-pulse-glow" style={{ animationDelay: '2s' }}></div>
            </div>

            {/* Code Editor Panel */}
            <div className="flex-1 flex flex-col border-r border-card-border bg-[#0A0F1E] min-h-[400px] z-10">
                <div className="h-14 glass border-b border-card-border px-4 flex items-center justify-between flex-shrink-0 relative">
                    <div className="flex items-center gap-3">
                        <div className="p-1.5 rounded bg-blue-500/10 border border-blue-500/20">
                            <FileCode className="w-4 h-4 text-primary" />
                        </div>
                        <div className="relative">
                            <button onClick={() => setIsDropdownOpen(!isDropdownOpen)} className="flex items-center gap-2 font-medium text-sm hover:text-primary transition-colors focus:outline-none">
                                {LANGUAGES[selectedLang].name}
                                <ChevronDown className={`w-3 h-3 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
                            </button>
                            <AnimatePresence>
                                {isDropdownOpen && (
                                    <motion.div
                                        initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 10 }}
                                        className="absolute top-full left-0 mt-2 w-48 bg-[#0A0F1E] border border-card-border rounded-xl shadow-2xl overflow-hidden z-50 py-1"
                                    >
                                        {(Object.keys(LANGUAGES) as LanguageKey[]).map((lang) => (
                                            <button key={lang} onClick={() => handleLanguageChange(lang)} className={`w-full px-4 py-2 text-left text-xs font-bold uppercase tracking-widest hover:bg-white/5 transition-colors ${selectedLang === lang ? 'text-primary bg-white/5' : 'text-secondary'}`}>
                                                {LANGUAGES[lang].name}
                                            </button>
                                        ))}
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    </div>

                    <div className="flex items-center gap-2">
                        <button onClick={resetCode} className="p-2 text-secondary hover:text-foreground hover:bg-card/50 rounded-lg transition-colors">
                            <RotateCcw className="w-4 h-4" />
                        </button>
                        <button onClick={handleAnalyze} disabled={analyzing} className="px-4 md:px-6 py-2 bg-primary hover:bg-blue-600 rounded-lg text-xs md:text-sm font-bold flex items-center gap-2 transition-all disabled:opacity-50 shadow-lg shadow-primary/20">
                            {analyzing ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>Analyzing...</> : <><Play className="w-4 h-4" />Analyze Code</>}
                        </button>
                    </div>
                </div>

                {/* Editor Area with Dynamic Highlighting */}
                <div className="flex-1 relative overflow-hidden group">
                    <textarea
                        ref={textAreaRef}
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        spellCheck={false}
                        // FIX: pl-[4.5rem] precisely matches the padding + the w-12 line number width!
                        className="absolute inset-0 w-full h-full py-6 pr-6 pl-[4.5rem] bg-transparent text-transparent caret-white font-mono text-sm leading-relaxed resize-none focus:outline-none z-10"
                    />
                    <pre className="absolute inset-0 py-6 pr-6 pl-6 font-mono text-sm leading-relaxed pointer-events-none overflow-auto">
                        <code className="block w-full">
                            {code.split('\n').map((line, i) => {
                                const lineNum = i + 1;
                                const flaggedIssue = scanResults.find(r => r.line_number === lineNum && r.label !== 1);

                                let highlightClass = '';
                                if (analyzed && flaggedIssue) {
                                    highlightClass = flaggedIssue.label === 0
                                        ? 'bg-red-500/20 border-l-2 border-red-500'
                                        : 'bg-yellow-500/20 border-l-2 border-yellow-500';
                                }

                                return (
                                    <div key={i} className={`flex w-full ${highlightClass}`}>
                                        <span className="text-gray-600 w-12 flex-shrink-0 text-right pr-4 select-none italic">{lineNum}</span>
                                        <span className="text-gray-400 whitespace-pre">
                                            {/* FIX: Regex matches words AND spaces perfectly, preserving exact cursor widths */}
                                            {line.match(/(\s+|\S+)/g)?.map((word, j) => {
                                                const isKeyword = ['import', 'from', 'def', 'async', 'return', 'class', 'try', 'except'].includes(word.trim());
                                                const isFunction = word.includes('(');
                                                return <span key={j} className={isKeyword ? 'text-purple-400' : isFunction ? 'text-yellow-300' : 'text-blue-300'}>{word}</span>;
                                            }) || line}
                                        </span>
                                    </div>
                                );
                            })}
                        </code>
                    </pre>
                </div>
            </div>

            {/* Dynamic Results Panel */}
            <div className="w-full lg:w-[420px] flex flex-col bg-background/80 backdrop-blur-xl border-l border-card-border h-full lg:h-auto overflow-auto z-10">
                <div className="h-14 glass border-b border-card-border px-6 flex items-center justify-between flex-shrink-0">
                    <h2 className="font-bold tracking-tight">AI Audit Results</h2>
                </div>

                <AnimatePresence mode="wait">
                    {!analyzed && !analyzing && (
                        <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex-1 flex flex-col items-center justify-center p-12 text-center space-y-6">
                            <div className="relative w-24 h-24 rounded-3xl glass border border-primary/40 flex items-center justify-center animate-float"><Sparkles className="w-10 h-10 text-primary" /></div>
                            <p className="font-extrabold text-xl text-foreground">Awaiting Analysis</p>
                        </motion.div>
                    )}

                    {analyzing && (
                        <motion.div key="analyzing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex-1 flex flex-col items-center justify-center p-12 space-y-8">
                            <p className="text-sm font-bold text-primary animate-pulse tracking-widest uppercase">Scanning Neural Patterns</p>
                        </motion.div>
                    )}

                    {analyzed && (
                        <motion.div key="results" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="flex-1 p-6 space-y-6">
                            {issues.length > 0 ? (
                                <>
                                    {issues.map((issue, idx) => (
                                        <motion.div key={idx} initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className={`glass p-6 rounded-2xl border ${issue.label === 0 ? 'border-red-500/30 bg-red-500/5' : 'border-yellow-500/30 bg-yellow-500/5'}`}>
                                            <span className={`text-[10px] font-black tracking-widest uppercase mb-1 ${issue.label === 0 ? 'text-red-500' : 'text-yellow-500'}`}>
                                                {issue.label_name} (Line {issue.line_number})
                                            </span>
                                            <div className="mt-2 p-3 rounded-xl bg-black/20 border border-white/5 font-mono text-xs text-secondary overflow-hidden text-ellipsis whitespace-nowrap">
                                                {issue.code}
                                            </div>
                                        </motion.div>
                                    ))}

                                    <button onClick={handleGenerateFix} className="w-full py-4 bg-foreground text-background rounded-xl font-bold hover:bg-gray-200 transition-all shadow-xl flex items-center justify-center gap-3">
                                        <Sparkles className="w-5 h-5" /> Generate Secure Fix
                                    </button>
                                </>
                            ) : (
                                <div className="p-8 text-center glass rounded-2xl border border-safe/30">
                                    <CheckCircle2 className="w-12 h-12 text-safe mx-auto mb-4" />
                                    <p className="font-bold text-safe">Zero vulnerabilities detected!</p>
                                </div>
                            )}
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>

            {/* AI Fix Overlay */}
            <AnimatePresence>
                {showFix && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md">
                        <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="w-full max-w-2xl glass rounded-3xl border border-primary/30 p-8 space-y-8 shadow-2xl">
                            <div className="flex justify-between items-center">
                                <h2 className="text-2xl font-black flex gap-3 items-center"><Sparkles className="text-primary" /> AI Proposed Fix</h2>
                                <button onClick={() => setShowFix(false)} className="text-secondary hover:text-white"><AlertCircle className="rotate-45" /></button>
                            </div>

                            <div className="glass rounded-xl border border-safe/30 overflow-hidden">
                                <div className="px-4 py-2 border-b border-safe/20 bg-safe/5 text-[10px] font-bold text-safe uppercase tracking-widest">Remediated Code</div>
                                <div className="p-6 bg-[#0A0F1E] font-mono text-sm text-blue-300 overflow-auto max-h-[300px]">
                                    {isFixing ? (
                                        <div className="flex items-center gap-3 animate-pulse text-secondary"><Sparkles className="w-4 h-4 animate-spin" /> Generating secure logic offline...</div>
                                    ) : (
                                        <pre><code>{fixedCode}</code></pre>
                                    )}
                                </div>
                            </div>

                            <button
                                onClick={() => {
                                    setShowFix(false);
                                    if (fixedCode) setCode(fixedCode);
                                    setAnalyzed(false);
                                    setScanResults([]);
                                }}
                                disabled={isFixing}
                                className="w-full py-4 bg-primary text-white rounded-xl font-bold hover:bg-blue-600 transition-all disabled:opacity-50"
                            >
                                Apply Fix Locally
                            </button>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}