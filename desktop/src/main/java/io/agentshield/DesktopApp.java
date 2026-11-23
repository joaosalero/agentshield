package io.agentshield;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class DesktopApp extends JFrame {
    private static final Color INK = new Color(14, 25, 43), MUTED = new Color(96, 112, 133);
    private static final Color NAVY = new Color(9, 21, 38), NAVY_2 = new Color(15, 35, 58);
    private static final Color BLUE = new Color(38, 104, 236), CYAN = new Color(27, 207, 185);
    private static final Color SURFACE = new Color(243, 247, 251), LINE = new Color(222, 230, 240);
    private static final Color DANGER = new Color(218, 59, 77), AMBER = new Color(225, 145, 28);
    private static final Font UI = new Font("Segoe UI", Font.PLAIN, 13);

    private final JTextField pid = field(8), policyPath = field(26), auditPath = field(20), auditKeyPath = field(18);
    private final JCheckBox strictPrivacy = new JCheckBox("Strict privacy mode");
    private final JLabel identity = new JLabel("Select a process to begin continuous exposure monitoring");
    private final JLabel pageTitle = title("Credentials", 27), pageSubtitle = label("Credential-like names visible to the selected AI agent", MUTED, 13);
    private final StatusPill status = new StatusPill();
    private final CardLayout pages = new CardLayout();
    private final JPanel pageDeck = new JPanel(pages);
    private final JLabel[] counts = {metric("0"), metric("0"), metric("0"), metric("0")};
    private final JButton start = new ModernButton("Start monitoring", BLUE, Color.WHITE);
    private final JButton stop = new ModernButton("Stop", new Color(231, 237, 245), INK);
    private final JButton verifyAudit = new ModernButton("Verify integrity", new Color(231, 237, 245), INK);
    private final JButton demo = new ModernButton("Launch Demo Lab", new Color(18, 156, 139), Color.WHITE);
    private final String executable;
    private volatile Process monitor, auditVerifier;
    private volatile Thread monitorWorker;
    private volatile boolean stopRequested;

    private static DefaultTableModel model(String... columns) { return new DefaultTableModel(columns, 0) { @Override public boolean isCellEditable(int r, int c) { return false; } }; }
    private final DefaultTableModel credentials = model("SEVERITY", "CREDENTIAL EXPOSURE", "SOURCE");
    private final DefaultTableModel resources = model("SEVERITY", "RESOURCE", "IDENTIFIER", "PROTOCOL", "LOCAL", "REMOTE", "STATE");
    private final DefaultTableModel findings = model("SEVERITY", "RULE", "FINDING", "EVIDENCE", "RECOMMENDED ACTION");
    private final DefaultTableModel policy = model("DECISION", "AREA", "OBSERVED ACCESS", "REASON", "STATUS");
    private final DefaultTableModel activity = model("TIME", "CHANGE", "SEVERITY", "AREA", "OBSERVED ACCESS", "STATUS");

    static List<String> buildMonitorCommand(String executable, String target, String policy, boolean strict) { return buildMonitorCommand(executable, target, policy, strict, "", ""); }
    static List<String> buildMonitorCommand(String executable, String target, String policy, boolean strict, String audit, String auditKey) { var c = new ArrayList<>(List.of(executable, "watch", target, "--interval", "1000", "--format", "tsv")); if (!policy.isBlank()) { c.add("--policy"); c.add(policy); } if (strict) { c.add("--privacy"); c.add("strict"); } if (!audit.isBlank()) { c.add("--audit"); c.add(audit); c.add("--audit-key"); c.add(auditKey); } return List.copyOf(c); }
    static Object[] policyRow(String[] f) { return f.length > 5 && f[0].equals("POLICY") ? new Object[]{f[1], f[2], f[3], f[4], f[5]} : null; }
    static Object[] resourceRow(String[] f) { return f.length > 3 && f[0].equals("RESOURCE") ? new Object[]{f[1], f[2], f[3], f.length > 4 ? f[4] : "", f.length > 5 ? f[5] : "", f.length > 6 ? f[6] : "", f.length > 7 ? f[7] : ""} : null; }
    static List<String> buildAuditVerifyCommand(String executable, String audit, String key) { return List.of(executable, "audit", "verify", audit, "--audit-key", key); }
    static String readBounded(InputStream input, int maximum) throws IOException { var out = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int total = 0, count; boolean truncated = false; while ((count = input.read(buffer)) >= 0) { int accepted = Math.min(count, Math.max(0, maximum - total)); if (accepted > 0) { out.write(buffer, 0, accepted); total += accepted; } if (accepted < count) truncated = true; } String value = out.toString(StandardCharsets.UTF_8); return truncated ? value + "\n[diagnostic output truncated]" : value; }
    static Object[] timelineRow(String[] f) { if (f.length <= 6 || !f[0].equals("CHANGE")) return null; try { return new Object[]{new Date(Long.parseLong(f[1])), f[2], f[3], f[4], f[5], f[6]}; } catch (NumberFormatException e) { return null; } }
    static void prependBounded(DefaultTableModel target, Object[] row, int maximum) { if (maximum < 1) throw new IllegalArgumentException("maximum must be positive"); target.insertRow(0, row); while (target.getRowCount() > maximum) target.removeRow(target.getRowCount() - 1); }

    private DesktopApp(String executable) {
        super("AgentShield — AI Agent Runtime Security"); this.executable = executable;
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE); setMinimumSize(new Dimension(1240, 780)); setPreferredSize(new Dimension(1440, 900));
        JPanel root = new JPanel(new BorderLayout()); root.setBackground(SURFACE); root.add(sidebar(), BorderLayout.WEST); root.add(workspace(), BorderLayout.CENTER);
        bindActions(); setContentPane(root); pack(); setLocationRelativeTo(null);
        addWindowListener(new WindowAdapter() { @Override public void windowClosing(WindowEvent e) { shutdown(); } });
    }

    private JPanel sidebar() {
        GradientPanel side = new GradientPanel(); side.setPreferredSize(new Dimension(250, 0)); side.setLayout(new BorderLayout()); side.setBorder(new EmptyBorder(28, 18, 22, 18));
        JPanel brand = transparent(new BorderLayout(12, 0)); brand.add(new ShieldMark(), BorderLayout.WEST);
        JPanel brandText = transparent(); brandText.setLayout(new BoxLayout(brandText, BoxLayout.Y_AXIS)); brandText.add(label("AGENTSHIELD", Color.WHITE, 17, Font.BOLD)); brandText.add(label("RUNTIME TRUST", new Color(132, 158, 184), 10, Font.BOLD)); brand.add(brandText, BorderLayout.CENTER);
        side.add(brand, BorderLayout.NORTH);
        JPanel navigation = transparent(); navigation.setLayout(new BoxLayout(navigation, BoxLayout.Y_AXIS)); navigation.setBorder(new EmptyBorder(52, 0, 0, 0));
        ButtonGroup group = new ButtonGroup();
        addNav(navigation, group, "Credentials", "Credential exposure", "credentials", credentials);
        addNav(navigation, group, "Open resources", "Files and connections", "resources", resources);
        addNav(navigation, group, "Risk findings", "Explainable threats", "findings", findings);
        addNav(navigation, group, "Policy decisions", "Allow, approve, deny", "policy", policy);
        addNav(navigation, group, "Access timeline", "Grants and revocations", "activity", activity);
        side.add(navigation, BorderLayout.CENTER);
        JPanel trust = new RoundedPanel(new Color(19, 46, 72), 18); trust.setLayout(new BorderLayout(10, 8)); trust.setBorder(new EmptyBorder(15, 15, 15, 15));
        trust.add(label("●  PRIVACY PROTECTED", new Color(89, 229, 196), 11, Font.BOLD), BorderLayout.NORTH);
        JTextArea copy = new JTextArea("Credential values are never collected. Only names and access metadata are observed."); copy.setFont(UI.deriveFont(11f)); copy.setForeground(new Color(183, 201, 219)); copy.setOpaque(false); copy.setLineWrap(true); copy.setWrapStyleWord(true); copy.setEditable(false); trust.add(copy);
        side.add(trust, BorderLayout.SOUTH); return side;
    }

    private void addNav(JPanel parent, ButtonGroup group, String name, String hint, String key, DefaultTableModel model) {
        NavButton button = new NavButton(name, hint); group.add(button); parent.add(button); parent.add(Box.createVerticalStrut(7));
        if (group.getButtonCount() == 1) button.setSelected(true);
        button.addActionListener(e -> { pages.show(pageDeck, key); pageTitle.setText(name); pageSubtitle.setText(hint); });
        pageDeck.add(tableCard(name, hint, model), key);
    }

    private JPanel workspace() {
        JPanel work = new JPanel(new BorderLayout(0, 18)); work.setBackground(SURFACE); work.setBorder(new EmptyBorder(27, 30, 26, 30));
        JPanel header = transparent(new BorderLayout(20, 8)); JPanel heading = transparent(); heading.setLayout(new BoxLayout(heading, BoxLayout.Y_AXIS)); heading.add(pageTitle); heading.add(Box.createVerticalStrut(4)); heading.add(pageSubtitle); header.add(heading, BorderLayout.WEST); header.add(status, BorderLayout.EAST); header.add(identity, BorderLayout.SOUTH); identity.setForeground(MUTED); identity.setFont(UI);
        JPanel top = transparent(new BorderLayout(0, 19)); top.add(header, BorderLayout.NORTH); top.add(metrics(), BorderLayout.CENTER); work.add(top, BorderLayout.NORTH);
        pageDeck.setOpaque(false); work.add(pageDeck, BorderLayout.CENTER); work.add(controlCenter(), BorderLayout.SOUTH); return work;
    }

    private JPanel metrics() {
        JPanel grid = transparent(new GridLayout(1, 4, 14, 0)); String[][] data = {{"CREDENTIALS", "Names exposed", "01"}, {"RESOURCES", "Files & connections", "02"}, {"FINDINGS", "Detected risks", "03"}, {"DECISIONS", "Policy evaluations", "04"}};
        for (int i = 0; i < data.length; i++) { RoundedPanel card = new RoundedPanel(Color.WHITE, 18); card.setLayout(new BorderLayout(12, 5)); card.setBorder(new EmptyBorder(16, 18, 16, 18)); JLabel marker = label(data[i][2], i == 2 ? DANGER : BLUE, 11, Font.BOLD); card.add(marker, BorderLayout.EAST); JPanel body = transparent(); body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS)); body.add(label(data[i][0], MUTED, 10, Font.BOLD)); body.add(Box.createVerticalStrut(3)); body.add(counts[i]); body.add(label(data[i][1], MUTED, 11)); card.add(body); grid.add(card); }
        return grid;
    }

    private JPanel tableCard(String name, String description, DefaultTableModel source) {
        RoundedPanel card = new RoundedPanel(Color.WHITE, 20); card.setLayout(new BorderLayout()); card.setBorder(new EmptyBorder(18, 20, 16, 20));
        JPanel heading = transparent(new BorderLayout()); JPanel copy = transparent(); copy.setLayout(new BoxLayout(copy, BoxLayout.Y_AXIS)); copy.add(title(name, 17)); copy.add(label(description, MUTED, 12)); heading.add(copy); heading.add(new Badge("SESSION DATA"), BorderLayout.EAST); card.add(heading, BorderLayout.NORTH);
        JTable table = new JTable(source); table.setFont(UI); table.setForeground(INK); table.setBackground(Color.WHITE); table.setGridColor(new Color(238, 242, 247)); table.setRowHeight(38); table.setIntercellSpacing(new Dimension(0, 1)); table.setShowVerticalLines(false); table.setAutoCreateRowSorter(true); table.setFillsViewportHeight(true); table.setDefaultRenderer(Object.class, new RiskRenderer()); table.getTableHeader().setFont(UI.deriveFont(Font.BOLD, 10f)); table.getTableHeader().setForeground(MUTED); table.getTableHeader().setBackground(new Color(248, 250, 253)); table.getTableHeader().setPreferredSize(new Dimension(0, 34)); table.getAccessibleContext().setAccessibleDescription(description);
        JScrollPane scroll = new JScrollPane(table); scroll.setBorder(new EmptyBorder(14, 0, 0, 0)); scroll.getViewport().setBackground(Color.WHITE);
        JPanel empty = transparent(new GridBagLayout()); JPanel emptyCopy = transparent(); emptyCopy.setLayout(new BoxLayout(emptyCopy, BoxLayout.Y_AXIS)); JLabel emptyTitle = title("No observed data yet", 18); emptyTitle.setAlignmentX(Component.CENTER_ALIGNMENT); JLabel emptyHint = label("Enter an agent PID to monitor live, or launch the safe Demo Lab.", MUTED, 13); emptyHint.setAlignmentX(Component.CENTER_ALIGNMENT); emptyCopy.add(emptyTitle); emptyCopy.add(Box.createVerticalStrut(8)); emptyCopy.add(emptyHint); empty.add(emptyCopy);
        CardLayout contentLayout = new CardLayout(); JPanel content = new JPanel(contentLayout); content.setOpaque(false); content.add(empty, "empty"); content.add(scroll, "data"); source.addTableModelListener(e -> contentLayout.show(content, source.getRowCount() == 0 ? "empty" : "data")); contentLayout.show(content, source.getRowCount() == 0 ? "empty" : "data"); card.add(content); return card;
    }

    private JPanel controlCenter() {
        RoundedPanel card = new RoundedPanel(new Color(234, 240, 248), 20); card.setLayout(new BorderLayout(16, 12)); card.setBorder(new EmptyBorder(16, 18, 16, 18));
        JPanel primary = transparent(new FlowLayout(FlowLayout.LEFT, 10, 0)); primary.add(label("MONITORING CONTROL", MUTED, 10, Font.BOLD)); primary.add(label("Agent PID", INK, 12, Font.BOLD)); primary.add(pid); start.setMnemonic('S'); primary.add(start); stop.setMnemonic('T'); stop.setEnabled(false); primary.add(stop); primary.add(strictPrivacy); strictPrivacy.setOpaque(false); strictPrivacy.setFont(UI); primary.add(Box.createHorizontalStrut(12)); primary.add(demo); card.add(primary, BorderLayout.NORTH);
        JPanel paths = transparent(); paths.setLayout(new BoxLayout(paths, BoxLayout.Y_AXIS));
        JPanel policyLine = transparent(new FlowLayout(FlowLayout.LEFT, 9, 2)); policyLine.add(label("Policy", MUTED, 11, Font.BOLD)); policyLine.add(policyPath); JButton browse = secondary("Browse…"); policyLine.add(browse); policyLine.add(label("Protected audit", MUTED, 11, Font.BOLD)); policyLine.add(auditPath); JButton browseAudit = secondary("Choose…"); policyLine.add(browseAudit); paths.add(policyLine);
        JPanel keyLine = transparent(new FlowLayout(FlowLayout.LEFT, 9, 2)); keyLine.add(label("Integrity key", MUTED, 11, Font.BOLD)); keyLine.add(auditKeyPath); JButton browseKey = secondary("Choose…"); keyLine.add(browseKey); verifyAudit.setMnemonic('V'); keyLine.add(verifyAudit); keyLine.add(label("Tamper-evident local audit trail", MUTED, 11)); paths.add(keyLine); card.add(paths, BorderLayout.CENTER);
        browse.addActionListener(e -> choose(policyPath, false)); browseAudit.addActionListener(e -> choose(auditPath, true)); browseKey.addActionListener(e -> choose(auditKeyPath, false)); return card;
    }

    private void bindActions() {
        pid.getAccessibleContext().setAccessibleName("Agent process ID"); policyPath.getAccessibleContext().setAccessibleName("Optional audit policy file"); auditPath.getAccessibleContext().setAccessibleName("Protected audit log file"); auditKeyPath.getAccessibleContext().setAccessibleName("Audit integrity key file"); strictPrivacy.getAccessibleContext().setAccessibleDescription("Redacts process, credential, resource, endpoint, and cgroup identifiers");
        start.addActionListener(e -> begin()); stop.addActionListener(e -> end()); verifyAudit.addActionListener(e -> verifyAudit()); demo.addActionListener(e -> startDemo());
        credentials.addTableModelListener(e -> updateCounts()); resources.addTableModelListener(e -> updateCounts()); findings.addTableModelListener(e -> updateCounts()); policy.addTableModelListener(e -> updateCounts());
    }

    private void choose(JTextField target, boolean save) { JFileChooser chooser = new JFileChooser(); int result = save ? chooser.showSaveDialog(this) : chooser.showOpenDialog(this); if (result == JFileChooser.APPROVE_OPTION) target.setText(chooser.getSelectedFile().getAbsolutePath()); }
    private void updateCounts() { counts[0].setText(String.valueOf(credentials.getRowCount())); counts[1].setText(String.valueOf(resources.getRowCount())); counts[2].setText(String.valueOf(findings.getRowCount())); counts[3].setText(String.valueOf(policy.getRowCount())); }

    static List<String> demoEvents() { return List.of(
        "SNAPSHOT\t{TIME}\tDEMO-2048\t12\tLOW\tdemo-agent\t1000\t0\tsandboxed\tdemo-lab",
        "CREDENTIAL\tMEDIUM\tDEMO_CLOUD_TOKEN\tsynthetic environment",
        "RESOURCE\tLOW\tfile\t/tmp/agentshield-demo/project-plan.txt\tfile\tlocal\tlocal\tOPEN",
        "FINDING\tHIGH\tAS-DEMO-001\tCredential name visible to the agent\tDEMO_CLOUD_TOKEN (value never created)\tUse a scoped credential broker",
        "CHANGE\t{TIME}\tGRANTED\tHIGH\tnetwork\thttps://example.invalid/api\tATTENTION",
        "RESOURCE\tHIGH\tnetwork_socket\thttps://example.invalid/api\ttcp\t127.0.0.1:42000\t192.0.2.10:443\tSIMULATED",
        "POLICY\tAPPROVAL\tnetwork\thttps://example.invalid/api\tExternal access requires approval\tATTENTION",
        "POLICY\tDENY\tcredential\tDEMO_ADMIN_KEY\tAdministrative credentials are prohibited\tBLOCKING",
        "CHANGE\t{TIME}\tREVOKED\tLOW\tnetwork\thttps://example.invalid/api\tRESOLVED"
    ); }

    static List<String> demoNarration() { return List.of(
        "A sandboxed demo agent establishes a low-risk baseline.",
        "A credential name becomes visible; its value is never created or collected.",
        "The agent opens a harmless temporary demo file.",
        "AgentShield correlates the exposure with an explainable high-severity rule.",
        "A new outbound access grant changes the agent's behavior profile.",
        "The simulated connection is attributed without contacting any real service.",
        "Policy requires explicit human approval for external network access.",
        "A prohibited administrative credential request is blocked deterministically.",
        "The risky access is revoked and the scenario is contained."
    ); }

    private void startDemo() {
        if (monitor != null) { JOptionPane.showMessageDialog(this, "Stop live monitoring before launching the Demo Lab."); return; }
        credentials.setRowCount(0); resources.setRowCount(0); findings.setRowCount(0); policy.setRowCount(0); activity.setRowCount(0);
        identity.setText("SIMULATION  •  No real credentials, personal files, or external connections are used");
        status.setState("DEMO LAB  •  STARTING", CYAN, false); demo.setEnabled(false); start.setEnabled(false);
        var events = demoEvents(); final int[] index = {0};
        javax.swing.Timer timer = new javax.swing.Timer(850, null);
        timer.addActionListener(e -> {
            if (index[0] >= events.size()) { timer.stop(); demo.setEnabled(true); start.setEnabled(true); status.setState("DEMO COMPLETE", new Color(22, 139, 118), false); identity.setText("SIMULATION COMPLETE  •  Evidence remained local  •  No real credentials, files, or connections were used"); return; }
            int step = index[0]; String event = events.get(index[0]++).replace("{TIME}", String.valueOf(System.currentTimeMillis()));
            identity.setText("SIMULATION  •  Step " + (step + 1) + " of " + events.size() + "  •  " + demoNarration().get(step));
            handle(event);
        });
        timer.setInitialDelay(250); timer.start();
    }

    private void begin() {
        String target = pid.getText().trim(); if (!target.matches("[1-9][0-9]*")) { JOptionPane.showMessageDialog(this, "Enter a valid process ID."); return; }
        String audit = auditPath.getText().trim(), key = auditKeyPath.getText().trim(); if (audit.isBlank() != key.isBlank()) { JOptionPane.showMessageDialog(this, "Choose both an audit log and its integrity key, or leave both empty."); return; }
        credentials.setRowCount(0); resources.setRowCount(0); findings.setRowCount(0); policy.setRowCount(0); activity.setRowCount(0); start.setEnabled(false); demo.setEnabled(false); stop.setEnabled(true); stopRequested = false; status.setState("MONITORING", CYAN, false);
        var command = buildMonitorCommand(executable, target, policyPath.getText().trim(), strictPrivacy.isSelected(), audit, key);
        monitorWorker = new Thread(() -> { try { Process process = new ProcessBuilder(command).start(); monitor = process; if (stopRequested) process.destroy(); var diagnostic = new AtomicReference<>(""); var errorReader = new Thread(() -> { try { diagnostic.set(readBounded(process.getErrorStream(), 65536).trim()); } catch (IOException e) { diagnostic.set("Unable to read monitor diagnostics: " + e.getMessage()); } }, "agentshield-diagnostics"); errorReader.start(); try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) { String line; while ((line = reader.readLine()) != null) handle(line); } int exit = process.waitFor(); errorReader.join(); String error = diagnostic.get(); if (exit != 0 && !error.isBlank()) SwingUtilities.invokeLater(() -> { status.setState("MONITOR FAILED", DANGER, true); JOptionPane.showMessageDialog(this, error, "Monitor error", JOptionPane.ERROR_MESSAGE); }); else SwingUtilities.invokeLater(() -> status.setState("MONITORING ENDED", MUTED, false)); } catch (IOException e) { SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, e.getMessage(), "Monitor error", JOptionPane.ERROR_MESSAGE)); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } finally { monitor = null; monitorWorker = null; SwingUtilities.invokeLater(() -> { start.setEnabled(true); demo.setEnabled(true); stop.setEnabled(false); }); } }, "agentshield-monitor"); monitorWorker.start();
    }

    private void handle(String line) { String[] p = line.split("\t", -1); Object[] resource = resourceRow(p), decision = policyRow(p), change = timelineRow(p); SwingUtilities.invokeLater(() -> { if (p.length > 8 && p[0].equals("SNAPSHOT")) { status.setRisk(p[3], p[4]); identity.setText("PID " + p[2] + "  •  " + p[5] + "  •  UID " + p[6] + "  •  capabilities 0x" + p[7] + "  •  " + p[8] + (p.length > 9 && !p[9].isBlank() ? "  •  cgroup " + p[9] : "")); credentials.setRowCount(0); resources.setRowCount(0); findings.setRowCount(0); policy.setRowCount(0); } else if (p.length > 3 && p[0].equals("CREDENTIAL")) credentials.addRow(new Object[]{p[1], p[2], p[3]}); else if (resource != null) resources.addRow(resource); else if (p.length > 5 && p[0].equals("FINDING")) findings.addRow(new Object[]{p[1], p[2], p[3], p[4], p[5]}); else if (decision != null) { policy.addRow(decision); if (p[5].equals("BLOCKING")) status.setState("BLOCKED BY POLICY", DANGER, true); } else if (change != null) { prependBounded(activity, change, 500); if (p[6].equals("ATTENTION")) status.setState("NEW ACCESS REQUIRES ATTENTION", AMBER, true); } }); }
    private void verifyAudit() { String audit = auditPath.getText().trim(), key = auditKeyPath.getText().trim(); if (audit.isBlank() || key.isBlank()) { JOptionPane.showMessageDialog(this, "Choose both the protected audit log and its integrity key."); return; } verifyAudit.setEnabled(false); new Thread(() -> { try { Process process = new ProcessBuilder(buildAuditVerifyCommand(executable, audit, key)).redirectErrorStream(true).start(); auditVerifier = process; String receipt = readBounded(process.getInputStream(), 65536).trim(); int exit = process.waitFor(); SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, exit == 0 ? "Audit integrity verified.\n\n" + receipt : receipt, exit == 0 ? "Audit verified" : "Audit verification failed", exit == 0 ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE)); } catch (IOException e) { SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, e.getMessage(), "Audit verification failed", JOptionPane.ERROR_MESSAGE)); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } finally { auditVerifier = null; SwingUtilities.invokeLater(() -> verifyAudit.setEnabled(true)); } }, "agentshield-audit-verifier").start(); }
    private void end() { stopRequested = true; Process process = monitor; if (process != null) process.destroy(); status.setState("MONITORING STOPPED", MUTED, false); }
    private void shutdown() { setEnabled(false); end(); Process verifier = auditVerifier; if (verifier != null) verifier.destroy(); new Thread(() -> { try { Thread worker = monitorWorker; if (worker != null) worker.join(3000); Process process = monitor; if (process != null && process.isAlive()) { process.destroyForcibly(); process.waitFor(1, TimeUnit.SECONDS); } } catch (InterruptedException e) { Thread.currentThread().interrupt(); Process process = monitor; if (process != null) process.destroyForcibly(); } SwingUtilities.invokeLater(() -> { dispose(); System.exit(0); }); }, "agentshield-shutdown").start(); }

    private static JTextField field(int columns) { JTextField f = new JTextField(columns); f.setFont(UI); f.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE), new EmptyBorder(7, 9, 7, 9))); return f; }
    private static JLabel label(String text, Color color, int size) { return label(text, color, size, Font.PLAIN); }
    private static JLabel label(String text, Color color, int size, int style) { JLabel l = new JLabel(text); l.setForeground(color); l.setFont(UI.deriveFont(style, size)); return l; }
    private static JLabel title(String text, int size) { return label(text, INK, size, Font.BOLD); }
    private static JLabel metric(String text) { return label(text, INK, 26, Font.BOLD); }
    private static JPanel transparent() { JPanel p = new JPanel(); p.setOpaque(false); return p; }
    private static JPanel transparent(LayoutManager layout) { JPanel p = new JPanel(layout); p.setOpaque(false); return p; }
    private static JButton secondary(String text) { return new ModernButton(text, new Color(222, 230, 240), INK); }

    private static class RoundedPanel extends JPanel { private final Color fill; private final int radius; RoundedPanel(Color fill, int radius) { this.fill = fill; this.radius = radius; setOpaque(false); } @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D) g.create(); g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON); g2.setColor(fill); g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius); g2.dispose(); super.paintComponent(g); } }
    private static final class GradientPanel extends JPanel { GradientPanel() { setOpaque(false); } @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D) g.create(); g2.setPaint(new GradientPaint(0, 0, NAVY_2, 0, getHeight(), NAVY)); g2.fillRect(0, 0, getWidth(), getHeight()); g2.dispose(); super.paintComponent(g); } }
    private static final class ShieldMark extends JComponent { ShieldMark() { setPreferredSize(new Dimension(42, 46)); } @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D) g.create(); g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON); Polygon p = new Polygon(new int[]{21, 38, 35, 21, 7, 4}, new int[]{2, 9, 30, 43, 30, 9}, 6); g2.setPaint(new GradientPaint(4, 2, CYAN, 38, 43, BLUE)); g2.fill(p); g2.setColor(Color.WHITE); g2.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)); g2.drawLine(13, 22, 19, 28); g2.drawLine(19, 28, 30, 16); g2.dispose(); } }
    private static class ModernButton extends JButton { private final Color fill; ModernButton(String text, Color fill, Color foreground) { super(text); this.fill = fill; setForeground(foreground); setFont(UI.deriveFont(Font.BOLD, 12f)); setBorder(new EmptyBorder(8, 15, 8, 15)); setFocusPainted(false); setContentAreaFilled(false); setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); } @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D) g.create(); g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON); g2.setColor(isEnabled() ? (getModel().isRollover() ? fill.brighter() : fill) : new Color(210, 217, 226)); g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12); g2.dispose(); super.paintComponent(g); } }
    private static final class NavButton extends JToggleButton { private final String hint; NavButton(String text, String hint) { super(text); this.hint = hint; setFont(UI.deriveFont(Font.BOLD, 13f)); setForeground(new Color(193, 209, 225)); setHorizontalAlignment(LEFT); setBorder(new EmptyBorder(13, 16, 25, 12)); setFocusPainted(false); setContentAreaFilled(false); setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); setMaximumSize(new Dimension(Integer.MAX_VALUE, 58)); } @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D) g.create(); g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON); if (isSelected() || getModel().isRollover()) { g2.setColor(isSelected() ? new Color(34, 72, 108) : new Color(24, 52, 80)); g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14); } if (isSelected()) { g2.setColor(CYAN); g2.fillRoundRect(4, 14, 3, 29, 3, 3); } g2.dispose(); super.paintComponent(g); Graphics2D t = (Graphics2D) g.create(); t.setFont(UI.deriveFont(10f)); t.setColor(new Color(130, 154, 178)); t.drawString(hint, 16, getHeight() - 10); t.dispose(); } }
    private static final class Badge extends JLabel { Badge(String text) { super("●  " + text); setForeground(new Color(22, 139, 118)); setFont(UI.deriveFont(Font.BOLD, 10f)); setBorder(new EmptyBorder(7, 10, 7, 10)); setOpaque(true); setBackground(new Color(226, 248, 242)); } }
    private static final class StatusPill extends RoundedPanel { private final JLabel text = label("●  NOT MONITORING", MUTED, 11, Font.BOLD); StatusPill() { super(new Color(229, 235, 243), 18); setLayout(new BorderLayout()); setBorder(new EmptyBorder(9, 14, 9, 14)); add(text); } void setState(String value, Color color, boolean alert) { text.setText((alert ? "▲  " : "●  ") + value); text.setForeground(color); } void setRisk(String score, String level) { int risk; try { risk = Integer.parseInt(score); } catch (NumberFormatException e) { risk = 0; } Color color = risk >= 75 ? DANGER : risk >= 40 ? AMBER : new Color(22, 139, 118); setState("RISK " + score + "/100  •  " + level.toUpperCase(), color, risk >= 40); } }
    private static final class RiskRenderer extends DefaultTableCellRenderer { @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) { Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column); setBorder(new EmptyBorder(0, 10, 0, 10)); if (!selected) { int modelRow = table.convertRowIndexToModel(row); StringBuilder combined = new StringBuilder(); for (int i = 0; i < table.getModel().getColumnCount(); i++) combined.append(' ').append(table.getModel().getValueAt(modelRow, i)); String s = combined.toString(); if (s.contains(" CRITICAL") || s.contains(" BLOCKING") || s.contains(" DENY")) { c.setBackground(new Color(255, 238, 241)); c.setForeground(new Color(166, 36, 55)); } else if (s.contains(" HIGH") || s.contains(" ATTENTION") || s.contains(" APPROVAL")) { c.setBackground(new Color(255, 248, 230)); c.setForeground(new Color(137, 83, 7)); } else { c.setBackground(row % 2 == 0 ? Color.WHITE : new Color(250, 252, 254)); c.setForeground(INK); } } return c; } }

    public static void main(String[] args) { String binary = args.length > 0 ? args[0] : "agentshield"; UIManager.put("ToolTip.font", UI); UIManager.put("OptionPane.messageFont", UI); UIManager.put("OptionPane.buttonFont", UI); SwingUtilities.invokeLater(() -> new DesktopApp(binary).setVisible(true)); }
}
