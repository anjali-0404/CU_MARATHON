import { NextResponse } from "next/server";
import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";

interface MlScanResult {
    line_number: number;
    code: string;
    label: number;
    label_name: string;
    confidence: number;
}

interface MlScanResponse {
    scan_results: MlScanResult[];
}

export async function POST(req: Request) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return new NextResponse("Unauthorized", { status: 401 });
        }

        const body = await req.json();
        const { code } = body;

        if (!code) {
            return new NextResponse("No code provided", { status: 400 });
        }

        // 1. Send code to local Flask ML Backend
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:7860";
        console.log(`Forwarding scan request to: ${apiUrl}/scan`);
        
        const flaskResponse = await fetch(`${apiUrl}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code }),
        });

        if (!flaskResponse.ok) {
            throw new Error("Failed to communicate with ML Backend");
        }

        const mlData: MlScanResponse = await flaskResponse.json();
        const scanResults = mlData.scan_results;

        // 2. Determine if the overall snippet has vulnerabilities
        const hasVulnerabilities = scanResults.some(
            (res) => res.label === 0 || res.label === 2
        );

        // 3. Save the scan and line-level issues to Prisma
        const savedScan = await prisma.scanResult.create({
            data: {
                userId: session.user.id,
                originalCode: code,
                isVulnerable: hasVulnerabilities,
                vulnerabilities: {
                    create: scanResults.map((res) => ({
                        lineNumber: res.line_number,
                        codeSnippet: res.code,
                        label: res.label,
                        labelName: res.label_name,
                        confidence: res.confidence,
                    })),
                },
            },
            include: {
                vulnerabilities: true, // Return vulnerabilities to the frontend
            }
        });

        return NextResponse.json({
            id: savedScan.id,
            vulnerabilities: savedScan.vulnerabilities,
        });

    } catch (error) {
        console.error("SCAN_ERROR", error);
        return new NextResponse("Internal Error", { status: 500 });
    }
}