package io.agentshield;

import java.util.List;
import java.util.Arrays;

public final class DesktopAppTest {
    public static void main(String[] args) {
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
        System.out.println("desktop command contract: OK");
    }
}
