package io.agentshield;

import java.util.List;
import java.util.Arrays;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.swing.table.DefaultTableModel;

public final class DesktopAppTest {
    public static void main(String[] args) throws Exception {
        var command=DesktopApp.buildMonitorCommand("agentshield","42","/secure/observe.policy",true);
        var expected=List.of("agentshield","watch","42","--interval","1000","--format","tsv","--policy","/secure/observe.policy","--privacy","strict");
        if(!command.equals(expected))throw new AssertionError("desktop policy command contract changed");
        var plain=DesktopApp.buildMonitorCommand("agentshield","7","",false);
        if(plain.contains("--policy")||plain.contains("--privacy"))throw new AssertionError("optional controls were added unexpectedly");
        var audited=DesktopApp.buildMonitorCommand("agentshield","9","",true,"/secure/audit.jsonl","/secure/audit.key");
        var expectedAudit=List.of("agentshield","watch","9","--interval","1000","--format","tsv","--privacy","strict","--audit","/secure/audit.jsonl","--audit-key","/secure/audit.key");
        if(!audited.equals(expectedAudit))throw new AssertionError("desktop authenticated audit command contract changed");
        var row=DesktopApp.policyRow("POLICY\tAPPROVAL\tcredential\t[credential name redacted]\tApproval required\tATTENTION".split("\\t",-1));
        var expectedRow=new Object[]{"APPROVAL","credential","[credential name redacted]","Approval required","ATTENTION"};
        if(!Arrays.equals(row,expectedRow))throw new AssertionError("desktop policy row contract changed");
        if(DesktopApp.policyRow(new String[]{"POLICY","DENY"})!=null)throw new AssertionError("malformed policy row accepted");
        var resource=DesktopApp.resourceRow("RESOURCE\tMEDIUM\tnetwork_socket\ttcp://203.0.113.8:443\ttcp\t192.0.2.4:42000\t203.0.113.8:443\tESTABLISHED".split("\\t",-1));
        var expectedResource=new Object[]{"MEDIUM","network_socket","tcp://203.0.113.8:443","tcp","192.0.2.4:42000","203.0.113.8:443","ESTABLISHED"};
        if(!Arrays.equals(resource,expectedResource))throw new AssertionError("desktop network attribution row contract changed");
        var verify=DesktopApp.buildAuditVerifyCommand("agentshield","/secure/audit.jsonl","/secure/audit.key");
        if(!verify.equals(List.of("agentshield","audit","verify","/secure/audit.jsonl","--audit-key","/secure/audit.key")))throw new AssertionError("desktop audit verification command changed");
        var timeline=DesktopApp.timelineRow("CHANGE\t1787352000000\tGRANTED\tHIGH\tnetwork\ttcp://203.0.113.8:443\tATTENTION".split("\\t",-1));
        if(timeline==null||!timeline[1].equals("GRANTED")||!timeline[5].equals("ATTENTION"))throw new AssertionError("desktop timeline projection changed");
        if(DesktopApp.timelineRow("CHANGE\tnot-a-time\tGRANTED\tHIGH\tnetwork\tx\tATTENTION".split("\\t",-1))!=null)throw new AssertionError("malformed timeline timestamp accepted");
        String diagnostic="0123456789";
        String bounded=DesktopApp.readBounded(new ByteArrayInputStream(diagnostic.getBytes(StandardCharsets.UTF_8)),5);
        if(!bounded.startsWith("01234")||!bounded.contains("truncated")||bounded.contains("56789"))throw new AssertionError("diagnostic bound failed");
        var history=new DefaultTableModel(new Object[]{"event"},0);
        DesktopApp.prependBounded(history,new Object[]{"first"},2);
        DesktopApp.prependBounded(history,new Object[]{"second"},2);
        DesktopApp.prependBounded(history,new Object[]{"third"},2);
        if(history.getRowCount()!=2||!history.getValueAt(0,0).equals("third")||!history.getValueAt(1,0).equals("second"))throw new AssertionError("timeline retention bound failed");
        System.out.println("desktop behavior contracts: OK");
    }
}
