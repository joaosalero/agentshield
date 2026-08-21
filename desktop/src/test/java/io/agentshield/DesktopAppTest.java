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
        var row=DesktopApp.policyRow("POLICY\tAPPROVAL\tcredential\t[credential name redacted]\tApproval required\tATTENTION".split("\\t",-1));
        var expectedRow=new Object[]{"APPROVAL","credential","[credential name redacted]","Approval required","ATTENTION"};
        if(!Arrays.equals(row,expectedRow))throw new AssertionError("desktop policy row contract changed");
        if(DesktopApp.policyRow(new String[]{"POLICY","DENY"})!=null)throw new AssertionError("malformed policy row accepted");
        System.out.println("desktop command contract: OK");
    }
}
