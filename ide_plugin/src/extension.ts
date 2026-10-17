/**
 * CodeGuardian VSCode Extension
 * Real-time security vulnerability detection
 */

import * as vscode from 'vscode';
import axios, { AxiosInstance } from 'axios';

interface Vulnerability {
    id: string;
    category: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    location: { file_path: string; start_line: number; end_line: number };
    cwe_id?: string;
}

interface Remediation {
    vulnerability_id: string;
    suggested_fix: string;
    rationale: string;
}

interface AnalysisResult {
    request_id: string;
    vulnerabilities: Vulnerability[];
    remediations: Remediation[];
    summary: { total_vulnerabilities: number; has_critical: boolean; has_high: boolean };
}

let diagnosticCollection: vscode.DiagnosticCollection;
let apiClient: AxiosInstance;
let analysisTimer: NodeJS.Timeout | undefined;
let statusBarItem: vscode.StatusBarItem;
const remediationCache = new Map<string, Remediation>();

export function activate(context: vscode.ExtensionContext) {
    console.log('CodeGuardian extension activated');
    
    diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguardian');
    context.subscriptions.push(diagnosticCollection);

    const config = vscode.workspace.getConfiguration('codeguardian');
    apiClient = axios.create({
        baseURL: config.get<string>('serverUrl') || 'http://localhost:8080',
        timeout: 30000,
    });

    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'codeguardian.analyzeFile';
    statusBarItem.text = '🛡️ CodeGuardian';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('codeguardian.analyzeFile', analyzeCurrentFile),
        vscode.commands.registerCommand('codeguardian.analyzeWorkspace', analyzeWorkspace),
        vscode.commands.registerCommand('codeguardian.applyFix', applyFix)
    );

    // Code actions
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['python', 'javascript', 'typescript', 'java', 'go'],
            new SecurityCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Real-time analysis
    if (config.get<boolean>('enableRealTimeAnalysis')) {
        context.subscriptions.push(
            vscode.workspace.onDidChangeTextDocument(e => scheduleAnalysis(e.document)),
            vscode.window.onDidChangeActiveTextEditor(e => e && scheduleAnalysis(e.document)),
            vscode.workspace.onDidSaveTextDocument(doc => analyzeDocument(doc))
        );
    }

    // Analyze current file on activation
    if (vscode.window.activeTextEditor) {
        scheduleAnalysis(vscode.window.activeTextEditor.document);
    }
}

function scheduleAnalysis(document: vscode.TextDocument, delay = 500) {
    const supported = ['python', 'javascript', 'typescript', 'java', 'go'];
    if (!supported.includes(document.languageId)) return;
    
    if (analysisTimer) clearTimeout(analysisTimer);
    analysisTimer = setTimeout(() => analyzeDocument(document), delay);
}

async function analyzeDocument(document: vscode.TextDocument) {
    try {
        const config = vscode.workspace.getConfiguration('codeguardian');
        const response = await apiClient.post<AnalysisResult>('/api/analyze/realtime', {
            code: document.getText(),
            language: document.languageId,
            file_path: document.uri.fsPath,
            policies: config.get<string[]>('policies') || ['OWASP_TOP_10'],
            include_remediation: true,
        });

        updateDiagnostics(document, response.data);
        response.data.remediations.forEach(r => remediationCache.set(r.vulnerability_id, r));
    } catch (error) {
        console.log('CodeGuardian: Server not available');
    }
}

function updateDiagnostics(document: vscode.TextDocument, result: AnalysisResult) {
    const config = vscode.workspace.getConfiguration('codeguardian');
    const threshold = config.get<string>('severityThreshold') || 'low';
    const severityOrder = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const minSeverity = severityOrder[threshold as keyof typeof severityOrder] || 0;

    const diagnostics: vscode.Diagnostic[] = result.vulnerabilities
        .filter(v => (severityOrder[v.severity] || 0) >= minSeverity)
        .map(vuln => {
            const range = new vscode.Range(
                Math.max(0, vuln.location.start_line - 1), 0,
                Math.max(0, vuln.location.end_line - 1), 100
            );
            
            const severity = (vuln.severity === 'critical' || vuln.severity === 'high')
                ? vscode.DiagnosticSeverity.Error
                : vuln.severity === 'medium'
                ? vscode.DiagnosticSeverity.Warning
                : vscode.DiagnosticSeverity.Information;

            const diag = new vscode.Diagnostic(
                range,
                `[${vuln.severity.toUpperCase()}] ${vuln.title}: ${vuln.description}`,
                severity
            );
            diag.source = 'CodeGuardian';
            diag.code = vuln.cwe_id || vuln.id;
            return diag;
        });

    diagnosticCollection.set(document.uri, diagnostics);

    // Update status bar
    const total = result.summary.total_vulnerabilities;
    statusBarItem.text = result.summary.has_critical ? `🔴 ${total} issues`
        : result.summary.has_high ? `🟠 ${total} issues`
        : total > 0 ? `🟡 ${total} issues`
        : '🟢 Secure';
}

async function analyzeCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No file open');
        return;
    }
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'CodeGuardian: Analyzing...',
    }, () => analyzeDocument(editor.document));
    
    vscode.window.showInformationMessage('CodeGuardian: Analysis complete');
}

async function analyzeWorkspace() {
    vscode.window.showInformationMessage('CodeGuardian: Workspace analysis coming soon');
}

async function applyFix(vulnId: string, fix: string, range: vscode.Range) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    
    await editor.edit(b => b.replace(range, fix));
    vscode.window.showInformationMessage('CodeGuardian: Fix applied');
}

class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        return context.diagnostics
            .filter(d => d.source === 'CodeGuardian')
            .flatMap(d => {
                const actions: vscode.CodeAction[] = [];
                const rem = remediationCache.get(d.code?.toString() || '');
                
                if (rem) {
                    const fix = new vscode.CodeAction(
                        `Fix: ${rem.rationale.slice(0, 50)}...`,
                        vscode.CodeActionKind.QuickFix
                    );
                    fix.command = {
                        command: 'codeguardian.applyFix',
                        title: 'Apply Fix',
                        arguments: [rem.vulnerability_id, rem.suggested_fix, d.range]
                    };
                    fix.diagnostics = [d];
                    fix.isPreferred = true;
                    actions.push(fix);
                }
                
                // Learn more action
                if (d.code?.toString().startsWith('CWE-')) {
                    const learn = new vscode.CodeAction('Learn more', vscode.CodeActionKind.Empty);
                    const cweNum = d.code.toString().replace('CWE-', '');
                    learn.command = {
                        command: 'vscode.open',
                        title: 'Open CWE',
                        arguments: [vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweNum}.html`)]
                    };
                    actions.push(learn);
                }
                
                return actions;
            });
    }
}

export function deactivate() {
    if (analysisTimer) clearTimeout(analysisTimer);
}
