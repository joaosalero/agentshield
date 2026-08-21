package io.agentshield;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class DesktopApp extends JFrame {
    private final JTextField pid=new JTextField(8);
    private final JLabel score=new JLabel("Not monitoring");
    private final JLabel identity=new JLabel("No process selected");
    private static DefaultTableModel model(String... columns){return new DefaultTableModel(columns,0){public boolean isCellEditable(int row,int column){return false;}};}
    private final DefaultTableModel credentials=model("Severity","Credential-like exposure","Source");
    private final DefaultTableModel resources=model("Severity","Resource type","Observed identifier");
    private final DefaultTableModel findings=model("Severity","Rule","Finding","Evidence","Recommended action");
    private final DefaultTableModel activity=model("Time","Change","Severity","Area","Observed access","Status");
    private final JButton start=new JButton("Start monitoring");
    private final JButton stop=new JButton("Stop");
    private final String executable;
    private Process monitor;

    private DesktopApp(String executable){
        super("AgentShield — AI Agent Runtime Security");this.executable=executable;setDefaultCloseOperation(EXIT_ON_CLOSE);setMinimumSize(new Dimension(1050,680));
        var root=new JPanel(new BorderLayout(12,12));root.setBorder(BorderFactory.createEmptyBorder(16,16,16,16));
        var header=new JPanel(new BorderLayout());var title=new JLabel("AgentShield  |  Live observed exposure");title.setFont(title.getFont().deriveFont(Font.BOLD,20f));header.add(title,BorderLayout.WEST);score.setFont(score.getFont().deriveFont(Font.BOLD,16f));header.add(score,BorderLayout.EAST);header.add(identity,BorderLayout.SOUTH);root.add(header,BorderLayout.NORTH);
        var tabs=new JTabbedPane();tabs.addTab("Credentials",new JScrollPane(new JTable(credentials)));tabs.addTab("Open resources",new JScrollPane(new JTable(resources)));tabs.addTab("Risk findings",new JScrollPane(new JTable(findings)));tabs.addTab("Access timeline",new JScrollPane(new JTable(activity)));root.add(tabs,BorderLayout.CENTER);
        var controls=new JPanel(new FlowLayout(FlowLayout.LEFT));controls.add(new JLabel("Agent PID:"));controls.add(pid);controls.add(start);stop.setEnabled(false);controls.add(stop);controls.add(new JLabel("Values are never collected — only credential names and access metadata."));root.add(controls,BorderLayout.SOUTH);
        start.addActionListener(e->begin());stop.addActionListener(e->end());setContentPane(root);pack();setLocationRelativeTo(null);
    }
    private void begin(){
        String target=pid.getText().trim();if(!target.matches("[1-9][0-9]*")){JOptionPane.showMessageDialog(this,"Enter a valid process ID.");return;}
        credentials.setRowCount(0);resources.setRowCount(0);findings.setRowCount(0);activity.setRowCount(0);start.setEnabled(false);stop.setEnabled(true);
        new Thread(()->{try{monitor=new ProcessBuilder(List.of(executable,"watch",target,"--interval","1000","--format","tsv")).start();try(var reader=new BufferedReader(new InputStreamReader(monitor.getInputStream(), StandardCharsets.UTF_8))){String line;while((line=reader.readLine())!=null)handle(line);}String error;try(var err=monitor.getErrorStream()){error=new String(err.readAllBytes(),StandardCharsets.UTF_8).trim();}int exit=monitor.waitFor();if(exit!=0&&!error.isBlank())SwingUtilities.invokeLater(()->{score.setText("Monitoring failed");JOptionPane.showMessageDialog(this,error,"Monitor error",JOptionPane.ERROR_MESSAGE);});else SwingUtilities.invokeLater(()->score.setText("Process ended / monitoring stopped"));}catch(IOException|InterruptedException ex){Thread.currentThread().interrupt();SwingUtilities.invokeLater(()->JOptionPane.showMessageDialog(this,ex.getMessage(),"Monitor error",JOptionPane.ERROR_MESSAGE));}finally{SwingUtilities.invokeLater(()->{start.setEnabled(true);stop.setEnabled(false);});}},"agentshield-monitor").start();
    }
    private void handle(String line){String[] p=line.split("\\t",-1);SwingUtilities.invokeLater(()->{if(p.length>8&&p[0].equals("SNAPSHOT")){score.setText("Risk "+p[3]+"/100 — "+p[4]);identity.setText("PID "+p[2]+" | "+p[5]+" | UID "+p[6]+" | capabilities 0x"+p[7]+" | "+p[8]);credentials.setRowCount(0);resources.setRowCount(0);findings.setRowCount(0);}else if(p.length>3&&p[0].equals("CREDENTIAL"))credentials.addRow(new Object[]{p[1],p[2],p[3]});else if(p.length>3&&p[0].equals("RESOURCE"))resources.addRow(new Object[]{p[1],p[2],p[3]});else if(p.length>5&&p[0].equals("FINDING"))findings.addRow(new Object[]{p[1],p[2],p[3],p[4],p[5]});else if(p.length>6&&p[0].equals("CHANGE")){activity.insertRow(0,new Object[]{new java.util.Date(Long.parseLong(p[1])),p[2],p[3],p[4],p[5],p[6]});while(activity.getRowCount()>500)activity.removeRow(activity.getRowCount()-1);if(p[6].equals("ATTENTION"))score.setText("ATTENTION — new "+p[3].toLowerCase()+" access detected");}});}
    private void end(){if(monitor!=null)monitor.destroy();score.setText("Monitoring stopped");}
    public static void main(String[] args){String binary=args.length>0?args[0]:"agentshield";SwingUtilities.invokeLater(()->new DesktopApp(binary).setVisible(true));}
}
