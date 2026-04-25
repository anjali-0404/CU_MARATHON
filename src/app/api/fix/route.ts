import { NextResponse } from "next/server";
import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";

export async function POST(req: Request) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return new NextResponse("Unauthorized", { status: 401 });
        }

        const body = await req.json();
        const parsedBody = body as {
            code?: string;
            scan_results?: Array<{
                line_number: number;
                code: string;
                label: number;
                label_name: string;
                confidence: number;
            }>;
            scanId?: string;
            scanID?: string;
            id?: string;
        };

        const scanId = parsedBody.scanId ?? parsedBody.scanID ?? parsedBody.id;
        const rawCode = parsedBody.code;
        const rawScanResults = parsedBody.scan_results;

        if (!scanId) {
            return new NextResponse("Missing scanId", { status: 400 });
        }

        let code = rawCode;
        let scanResults = rawScanResults;

        // Reports page sends only scanId; resolve source code and scan results from DB.
        if (!code || !scanResults) {
            const existingScan = await prisma.scanResult.findFirst({
                where: { id: scanId, userId: session.user.id },
                include: { vulnerabilities: true },
            });

            if (!existingScan) {
                return new NextResponse("Scan not found", { status: 404 });
            }

            code = existingScan.originalCode;
            scanResults = existingScan.vulnerabilities.map((v) => ({
                line_number: v.lineNumber,
                code: v.codeSnippet,
                label: v.label,
                label_name: v.labelName,
                confidence: v.confidence,
            }));
        }

        if (!code || !scanResults) {
            return new NextResponse("Missing required fields", { status: 400 });
        }

        // 1. Define the API URL exactly ONCE
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || "https://shaiiiikh1305-backend.hf.space";
        
        // 2. Send the code and vulnerabilities to the ML Backend
        const flaskResponse = await fetch(`${apiUrl}/fix`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code, scan_results: scanResults }),
        });

        if (!flaskResponse.ok) {
            throw new Error("Failed to communicate with ML Backend");
        }

        const mlData = await flaskResponse.json();
        const fixedCode = mlData.fixed_code;

        // 3. Save the fixed code back to the Prisma database
        if (fixedCode) {
            await prisma.scanResult.updateMany({
                where: { id: scanId, userId: session.user.id },
                data: { fixedCode: fixedCode },
            });
        }

        return NextResponse.json({ fixed_code: fixedCode });

    } catch (error) {
        console.error("FIX_ERROR", error);
        return new NextResponse("Internal Error", { status: 500 });
    }
}