// src/app/(app)/dashboard/page.tsx
'use client';

import { useState, useEffect } from 'react';
import { 
    ShieldCheck, AlertTriangle, Code2, 
    Terminal, Download, Activity, Zap, ChevronRight 
} from 'lucide-react';
import { motion } from 'framer-motion';
import Link from 'next/link';

interface ScanHistoryItem {
    id: string;
    realId: string;
    project: string;
    branch: string;
    status: string;
    risk: string;
    score: string;
    date: string;
    language: string;
}

export default function Dashboard() {
    const [scans, setScans] = useState<ScanHistoryItem[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isGenerating, setIsGenerating] = useState(false);

    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                const res = await fetch('/api/history');
                if (res.ok) {
                    const data = await res.json();
                    setScans(data);
                }
            } catch (error) {
                console.error("Failed to load dashboard data", error);
            } finally {
                setIsLoading(false);
            }
        };
        fetchDashboardData();
    }, []);

    const handleGeneratePDF = async () => {
        setIsGenerating(true);
        try {
            const res = await fetch('/api/history/export');
            if (!res.ok) {
                throw new Error('Failed to generate report');
            }

            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;

            const contentDisposition = res.headers.get('Content-Disposition');
            const fileNameMatch = contentDisposition?.match(/filename=([^;]+)/i);
            const fileName = fileNameMatch?.[1]?.replace(/"/g, '') || `codetrust-forensic-report-${Date.now()}.pdf`;

            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        } catch (error) {
            console.error('REPORT_EXPORT_ERROR', error);
            alert('Unable to download report right now. Please try again.');
        } finally {
            setIsGenerating(false);
        }
    };

    // Calculate Dynamic Stats
    const totalScans = scans.length;
    const criticalScans = scans.filter(s => s.risk === 'CRITICAL' || s.risk === 'HIGH').length;
    const avgScore = totalScans > 0 
        ? (scans.reduce((acc, curr) => acc + parseFloat(curr.score), 0) / totalScans).toFixed(1) 
        : '10.0';
    
    // Determine overall system health color
    const healthColor = parseFloat(avgScore) >= 8.5 ? 'text-safe' : parseFloat(avgScore) >= 6.0 ? 'text-hallucinated' : 'text-vulnerable';

    const topStats = [
        { 
            title: "System Integrity", 
            value: `${avgScore}/10`, 
            sub: "Overall Codebase Health", 
            icon: Activity,
            color: healthColor
        },
        { 
            title: "Active Threats", 
            value: criticalScans.toString(), 
            sub: "Critical & High Risk", 
            icon: AlertTriangle,
            color: criticalScans > 0 ? "text-vulnerable" : "text-safe"
        },
        { 
            title: "Secure Archives", 
            value: (totalScans - criticalScans).toString(), 
            sub: "Passed Neural Audit", 
            icon: ShieldCheck,
            color: "text-safe"
        },
        { 
            title: "Total Audits", 
            value: totalScans.toString(), 
            sub: "All-time Scans", 
            icon: Zap,
            color: "text-primary"
        }
    ];

    return (
        <div className="p-4 md:p-8 space-y-8 max-w-7xl mx-auto">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 relative z-10">
                <div className="space-y-2">
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-[10px] font-black uppercase tracking-widest mb-2">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
                        </span>
                        System Online
                    </div>
                    <h1 className="text-3xl md:text-5xl font-black italic tracking-tight leading-[1.15] pb-1">
                        Neural <span className="gradient-text">Command</span>
                    </h1>
                    <p className="text-secondary text-sm md:text-base font-medium max-w-xl">
                        Real-time forensic analysis and autonomous threat detection for your AI-generated infrastructure.
                    </p>
                </div>

                <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
                    <Link href="/analyze" className="px-5 sm:px-6 py-3 bg-primary text-background rounded-xl text-xs font-black uppercase tracking-widest hover:bg-primary/90 transition-all shadow-[0_0_20px_rgba(255,255,255,0.3)] active:scale-95 flex items-center justify-center gap-2">
                        <Terminal className="w-4 h-4" /> New Audit
                    </Link>
                    <button 
                        onClick={handleGeneratePDF}
                        disabled={isGenerating}
                        className="px-5 sm:px-6 py-3 glass border border-card-border rounded-xl text-xs font-black uppercase tracking-widest hover:bg-card hover:border-primary/30 transition-all active:scale-95 flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                        {isGenerating ? <Activity className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                        Report
                    </button>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {topStats.map((stat, i) => (
                    <motion.div 
                        key={i}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.1 }}
                        className="glass p-6 rounded-3xl border border-card-border hover:border-primary/30 transition-all group relative overflow-hidden"
                    >
                        <div className="absolute -right-4 -top-4 w-24 h-24 bg-card/30 rounded-full blur-2xl group-hover:bg-primary/10 transition-colors duration-500"></div>
                        <div className="flex justify-between items-start mb-4 relative z-10">
                            <p className="text-[10px] text-secondary uppercase font-black tracking-widest">{stat.title}</p>
                            <stat.icon className={`w-5 h-5 ${stat.color} opacity-80`} />
                        </div>
                        <div className="relative z-10">
                            <h3 className={`text-4xl font-black mb-1 ${stat.color}`}>{stat.value}</h3>
                            <p className="text-xs text-secondary font-medium">{stat.sub}</p>
                        </div>
                    </motion.div>
                ))}
            </div>

            {/* Recent Scans Table */}
            <div className="glass rounded-3xl border border-card-border overflow-hidden shadow-2xl shadow-primary/5">
                <div className="p-6 border-b border-card-border bg-card/30 flex justify-between items-center">
                    <div>
                        <h3 className="text-lg font-black italic">Recent Audits</h3>
                        <p className="text-xs text-secondary font-medium">Latest forensic scans across your repositories</p>
                    </div>
                    <Link href="/history" className="text-xs text-primary font-bold hover:underline hidden sm:block">View All Archives</Link>
                </div>
                
                <div className="overflow-x-auto">
                    <table className="w-full min-w-[620px] text-left border-collapse">
                        <thead>
                            <tr className="bg-card/20 text-[10px] font-black uppercase tracking-widest text-secondary border-b border-card-border">
                                <th className="px-6 py-4">ID</th>
                                <th className="px-6 py-4">Target</th>
                                <th className="px-6 py-4">Status</th>
                                <th className="px-6 py-4">Risk</th>
                                <th className="px-6 py-4 text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-card-border/50">
                            {isLoading ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-12 text-center text-secondary">
                                        <Activity className="w-6 h-6 animate-spin mx-auto mb-2" />
                                        <p className="text-xs font-bold uppercase tracking-widest">Loading Telemetry...</p>
                                    </td>
                                </tr>
                            ) : scans.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-12 text-center text-secondary font-medium">
                                        No recent audits found. Run a new scan to populate telemetry.
                                    </td>
                                </tr>
                            ) : (
                                scans.slice(0, 5).map((scan, i) => (
                                    <motion.tr 
                                        key={scan.realId}
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: i * 0.1 }}
                                        className="hover:bg-primary/5 transition-colors group"
                                    >
                                        <td className="px-6 py-4 font-mono text-xs text-primary font-bold">{scan.id}</td>
                                        <td className="px-6 py-4">
                                            <div className="flex items-center gap-3">
                                                <Code2 className="w-4 h-4 text-secondary group-hover:text-primary transition-colors" />
                                                <span className="text-sm font-bold">{scan.project}</span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider text-secondary">
                                                <span className="w-1.5 h-1.5 rounded-full bg-safe shadow-[0_0_8px_rgba(34,197,94,0.5)]"></span>
                                                Completed
                                            </span>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-1 rounded-md border ${
                                                scan.risk === 'CRITICAL' ? 'bg-vulnerable/10 text-vulnerable border-vulnerable/30' :
                                                scan.risk === 'HALLUCINATED' || scan.risk === 'HIGH' ? 'bg-hallucinated/10 text-hallucinated border-hallucinated/30' :
                                                'bg-safe/10 text-safe border-safe/30'
                                            }`}>
                                                {scan.risk}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <Link href={`/reports?scanId=${scan.realId}`} className="inline-flex p-2 rounded-lg hover:bg-card border border-transparent hover:border-card-border transition-all text-secondary hover:text-primary">
                                                <ChevronRight className="w-4 h-4" />
                                            </Link>
                                        </td>
                                    </motion.tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}